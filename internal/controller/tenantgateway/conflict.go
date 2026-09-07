/*
Copyright 2026 The Cozystack Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tenantgateway

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	gatewayv1alpha1 "github.com/cozystack/cozystack/api/gateway/v1alpha1"
)

// routeKind discriminates HTTPRoute vs TLSRoute when stamping
// RouteParentStatus back. Without this, status writes would target
// the wrong resource type entirely.
type routeKind int

const (
	routeKindHTTP routeKind = iota
	routeKindTLS
)

// ControllerName is the value used in HTTPRoute.Status.Parents[].ControllerName
// for entries written by this reconciler. Distinct from any GatewayClass
// controllerName (Cilium etc.) so multiple controllers can coexist.
const ControllerName gatewayv1.GatewayController = "gateway.cozystack.io/tenantgateway-controller"

// routeRef is a lightweight identifier of an HTTPRoute or TLSRoute
// as far as hostname-conflict resolution is concerned. The kind
// field is required so status updates write to the right resource
// type — TLSRoute and HTTPRoute may share namespace/name but live
// at different GVKs.
type routeRef struct {
	kind      routeKind
	namespace string
	name      string
	parentRef gatewayv1.ParentReference // exact ref the route used to attach
	// forwards records whether the route resolves at least one backend,
	// for routeKindTLS only — an HTTPRoute's is neither set nor read,
	// because no decision here consults an HTTPRoute's backends.
	//
	// It sits in a type used as a map key, which is safe because it is
	// derived once per route per pass: every ref built from one route
	// carries the same value, so the field cannot split that route's
	// entries across two keys.
	forwards bool
}

// servableOn reports whether ref could be served on hostname h by any
// passthrough listener this TenantGateway renders.
//
// The question is per route, not per hostname, and that is the whole
// point: a claim can overlap several reserved hostnames, so "some
// listener here admits every namespace" is true of the claim while
// being false of the listener this particular route asked for. A
// sectionName pins the route to one listener, and then only that
// listener's own hostname and attach set decide.
//
// byHostname maps each rendered passthrough hostname to the listener
// answering it, which carries the port it is published on and whether
// it admits the publishing tenant alone, as the native-port ones do.
// The caller is expected to have found at least one entry overlapping
// h before asking; a hostname nothing answers is a different shape,
// built by the caller with its own cause.
//
// sections maps a rendered passthrough listener name to the hostname it
// answers, and holds nothing else, so a sectionName absent from it
// names no passthrough listener. That covers two shapes and they do not
// get the same answer. A name carrying the passthrough prefix is one
// this controller renders the whole namespace of, so its absence is a
// fact: the route attaches to nothing, and it is told so. A name
// outside the prefix belongs to another listener family, the
// HTTPS-terminate ones among them, whose set is what the caller's loop
// is still computing; there the route is unserved for a reason this
// function does not model, so it comes back with withdrawnNone and the
// caller writes nothing rather than guessing. Either way it is not
// servable, which matters on its own, because this verdict is also
// membership in the ownership race and a route that can never attach
// must not take a hostname away from one that can.
//
// On refusal the second return says which leg failed, because the two
// send an operator to different places and one of them can fire on a
// route inside the tenant, where a namespace refusal would contradict
// the object it is written on.
func servableOn(ref routeRef, h, tenantNamespace string, byHostname map[string]passthroughListener, sections map[string]string) (bool, withdrawalCause, string) {
	pinned := ""
	if ref.parentRef.SectionName != nil {
		name := string(*ref.parentRef.SectionName)
		named, exists := sections[name]
		if !exists {
			// Inside the passthrough listener namespace the answer is
			// knowable, because every listener there is rendered from
			// this spec: a name absent from sections names none, so the
			// route attaches to nothing whatever answers its hostname.
			// Outside it the name belongs to a listener family this
			// pass cannot enumerate — the terminate listeners are the
			// output of the loop this feeds, so their names are not
			// settled while it runs — and a refusal would be a guess.
			if strings.HasPrefix(name, passthroughListenerPrefix) {
				return false, withdrawnNoSuchSection, ""
			}
			return false, withdrawnNone, ""
		}
		pinned = named
	}
	// refusedBy is the name of a listener that matched and then turned
	// this route away, and it is the third return because the message
	// has to name that one. The caller's own pick is the smallest
	// overlapping name, chosen for stable text, and on a claim covering
	// several reserved names that is regularly a listener which would
	// have admitted the route. Smallest is also what makes it stable
	// here: the map iterates in no order, so without it two reconciles
	// could name two different refusers and rewrite the condition.
	refusedBy := ""
	sectionAnswers := false
	portAnswers := ref.parentRef.Port == nil
	for rh, l := range byHostname {
		if !hostnamesOverlap(rh, h) {
			continue
		}
		if pinned != "" && rh != pinned {
			continue
		}
		sectionAnswers = true
		// A parentRef may pin the listener by port as well as by name,
		// and Gateway API requires both to match when both are given.
		// Without this a route naming port 443 attaches to nothing on a
		// native-port listener and is still told it is fine.
		if ref.parentRef.Port != nil && int32(*ref.parentRef.Port) != l.port {
			continue
		}
		portAnswers = true
		if l.tenantOnly && ref.namespace != tenantNamespace {
			if refusedBy == "" || rh < refusedBy {
				refusedBy = rh
			}
			continue
		}
		return true, withdrawnNone, ""
	}
	// Reaching here with a pinned listener that never matched the name
	// means the sectionName is the reason, whatever the namespace is.
	if pinned != "" && !sectionAnswers {
		return false, withdrawnSectionMismatch, ""
	}
	// The name matched and the port did not. Reported apart from the
	// sectionName case because the field the route's owner edits is a
	// different one, and apart from the namespace case because the
	// route may well be inside the tenant.
	if !portAnswers {
		return false, withdrawnPortMismatch, ""
	}
	return false, withdrawnForeignNamespace, refusedBy
}

// rankRouteRefs orders claimants the way ownership decides them:
// cozy-* namespaces first, then by namespace and name. Shared rather
// than inlined because a hostname a passthrough listener answers has
// its race recounted over the TLSRoutes alone, and a second copy of
// the order would let the two counts disagree about who won.
func rankRouteRefs(refs []routeRef) {
	sort.Slice(refs, func(i, j int) bool {
		ic := strings.HasPrefix(refs[i].namespace, "cozy-")
		jc := strings.HasPrefix(refs[j].namespace, "cozy-")
		if ic != jc {
			return ic // cozy-* sorts first
		}
		if refs[i].namespace != refs[j].namespace {
			return refs[i].namespace < refs[j].namespace
		}
		return refs[i].name < refs[j].name
	})
}

// dropLostHostname removes one hostname from a route's loser record,
// deleting the entry when nothing is left, so an empty slice never
// reads as "lost something".
func dropLostHostname(losers map[routeRef][]string, ref routeRef, hostname string) {
	if rest := slices.DeleteFunc(losers[ref], func(lost string) bool { return lost == hostname }); len(rest) > 0 {
		losers[ref] = rest
	} else {
		delete(losers, ref)
	}
}

// resolveHostnameOwners decides who wins when more than one route
// claims the same hostname, and returns the routes that lost:
// routeRef -> []hostname for which this route is NOT the winner.
//
// The winners are resolved but not returned, because ownership decides
// route status and not what gets rendered. A hostname carries at most
// one listener however many routes claim it, and runReconcileSteps
// derives that from the claims themselves, so a winner of the wrong
// kind cannot take a terminate listener away from an HTTPRoute that
// also claimed the name.
//
// Rule: cozy-* namespace beats anything else; within the same priority
// tier the route with the lexicographically smallest namespace/name
// pair wins (deterministic).
func resolveHostnameOwners(claims map[string][]routeRef) map[routeRef][]string {
	losers := make(map[routeRef][]string)

	for hostname, refs := range claims {
		if len(refs) == 0 {
			continue
		}
		rankRouteRefs(refs)
		winner := refs[0]
		for _, lr := range refs[1:] {
			// Same-namespace routes claiming the same hostname are
			// not a conflict — Gateway API merges them by path /
			// headers / etc. Only cross-namespace claims are a
			// hijack signal.
			if lr.namespace == winner.namespace {
				continue
			}
			losers[lr] = append(losers[lr], hostname)
		}
	}
	return losers
}

// withdrawalCause names why the controller declined to serve a
// hostname. Named rather than inferred from an empty field, because
// the cases read differently to an operator and the difference decides
// where they go looking: a namespace refusal sends them to the attach
// list, a section mismatch to the route's own parentRef.
type withdrawalCause int

const (
	// withdrawnNone: no cause, returned alongside a servable verdict.
	// Explicit rather than the zero value of a real cause, so that
	// "nothing was withdrawn" cannot be read as a decision.
	withdrawnNone withdrawalCause = iota
	// withdrawnAnswered: a passthrough listener answers the name, so no
	// terminate listener is rendered for it.
	withdrawnAnswered
	// withdrawnUnanswered: nothing answers the name at all.
	withdrawnUnanswered
	// withdrawnForeignNamespace: a native-port listener answers the
	// name but admits only the tenant's own namespace, so this route
	// cannot attach to it however the hostname resolves.
	withdrawnForeignNamespace
	// withdrawnSectionMismatch: the route pinned itself to a listener
	// by sectionName, that listener exists, and it answers a different
	// hostname. Distinct from the namespace case because it happens to
	// routes inside the tenant too, where blaming the namespace states
	// something the object itself contradicts.
	withdrawnSectionMismatch
	// withdrawnPortMismatch: the route pinned itself to a listener by
	// parentRef.port, a listener answers its hostname, and it is
	// published on another port. Gateway API requires a pinned port to
	// match the selected listener, so the route attaches to nothing.
	withdrawnPortMismatch
	// withdrawnNoSuchSection: the route pinned itself by sectionName to
	// a passthrough listener this Gateway does not render. Separate
	// from withdrawnSectionMismatch, where the named listener exists
	// and answers another hostname: there the operator moves the route
	// or the hostname, here the name itself is wrong.
	withdrawnNoSuchSection
	// withdrawnKindNotAdmitted: an HTTPRoute pinned itself by
	// sectionName to a rendered passthrough listener, which forwards a
	// stream it never terminates and takes TLSRoute alone by protocol.
	// The only cause that judges a route's kind, and the only one an
	// HTTPRoute reaches through its sectionName; the section causes
	// above are reached by TLSRoutes, whose kind a passthrough listener
	// does take.
	withdrawnKindNotAdmitted
)

// withdrawnHostname pairs a hostname the controller declined to serve
// with the passthrough hostname involved, empty when the cause is that
// nothing answers it. The pair is carried rather than the claimed name
// alone because a wildcard entry is not derivable from the route: the
// route claims pg.db.<apex> and the spec that took it away says
// *.db.<apex>.
type withdrawnHostname struct {
	hostname   string
	answeredBy string
	cause      withdrawalCause
	// section carries the sectionName that missed, for
	// withdrawnSectionMismatch and withdrawnNoSuchSection. The message
	// has to name it, because it is the field the route's owner edits.
	// answeredBy then carries what the named listener does answer, and
	// is empty for withdrawnNoSuchSection, where it answers nothing.
	section string
	// port carries the parentRef port that missed, for
	// withdrawnPortMismatch only, with answeredBy naming the listener
	// that does answer the hostname on a port of its own.
	port int32
}

// describeWithdrawn renders the pairs in a stable order, dropping
// repeats: one route may list a hostname twice, since Gateway API
// declares spec.hostnames a plain array. The message is rebuilt on
// every reconcile, so an unstable order would rewrite the condition
// each pass and churn the route's status forever.
//
// Each cause is rendered separately, because a route hit by more than
// one of them has to be told about each.
func describeWithdrawn(hostnames []withdrawnHostname) withdrawnByCause {
	var withListener, without, elsewhere, wrongSection, onAnotherPort, noSuchSection, refusedKind []string
	for _, h := range hostnames {
		switch h.cause {
		case withdrawnKindNotAdmitted:
			refusedKind = append(refusedKind, fmt.Sprintf("%s (sectionName %s)", h.hostname, h.section))
		case withdrawnNoSuchSection:
			noSuchSection = append(noSuchSection, fmt.Sprintf("%s (sectionName %s)", h.hostname, h.section))
		case withdrawnSectionMismatch:
			wrongSection = append(wrongSection, fmt.Sprintf("%s (sectionName %s answers %s)", h.hostname, h.section, h.answeredBy))
		case withdrawnPortMismatch:
			onAnotherPort = append(onAnotherPort, fmt.Sprintf("%s (port %d, answered on another port)", h.hostname, h.port))
		case withdrawnUnanswered:
			without = append(without, h.hostname)
		case withdrawnForeignNamespace:
			// The pair is only worth printing when it says something the
			// hostname does not: for a wildcard claim the matched entry
			// is a different string, for a concrete one it is the same.
			if h.answeredBy == h.hostname {
				elsewhere = append(elsewhere, h.hostname)
			} else {
				elsewhere = append(elsewhere, fmt.Sprintf("%s (matched by %s)", h.hostname, h.answeredBy))
			}
		case withdrawnAnswered:
			withListener = append(withListener, fmt.Sprintf("%s (answered by %s)", h.hostname, h.answeredBy))
		}
	}
	sort.Strings(withListener)
	sort.Strings(without)
	sort.Strings(elsewhere)
	sort.Strings(wrongSection)
	sort.Strings(onAnotherPort)
	sort.Strings(noSuchSection)
	sort.Strings(refusedKind)
	return withdrawnByCause{
		answered:      strings.Join(slices.Compact(withListener), ", "),
		unserved:      strings.Join(slices.Compact(without), ", "),
		foreign:       strings.Join(slices.Compact(elsewhere), ", "),
		mismatched:    strings.Join(slices.Compact(wrongSection), ", "),
		wrongPort:     strings.Join(slices.Compact(onAnotherPort), ", "),
		absentSection: strings.Join(slices.Compact(noSuchSection), ", "),
		refusedKind:   strings.Join(slices.Compact(refusedKind), ", "),
	}
}

// withdrawnByCause holds one rendered hostname list per refusal cause,
// each empty when no hostname on the route hit that cause. Named fields
// rather than a return list: every one is a string, so a positional
// form binds one interchangeable value per cause at the call site and a
// swapped pair compiles.
type withdrawnByCause struct {
	answered      string
	unserved      string
	foreign       string
	mismatched    string
	wrongPort     string
	absentSection string
	refusedKind   string
}

// updateRouteStatuses writes RouteParentStatus entries under our
// ControllerName, one per (route, parentRef) tuple that attached to
// this TenantGateway. Accepted=True for tuples not in losers,
// Accepted=False with Reason=HostnameConflict for tuples that lost
// at least one hostname race. Other controllers' entries (Cilium
// etc.) are untouched.
//
// allRefs is the full set of (route, parentRef) tuples observed by
// collectHostnameClaims — without it, multi-parentRef routes would
// only get a status entry for whichever ref happened to win the
// per-hostname race, dropping per-section visibility for the others.
//
// withdrawn carries the tuples the controller declined to serve. None
// of them lost a race, so HostnameConflict would misname the cause,
// and what separates the rest is how precisely Gateway API can name
// the refusal. Two of Gateway API's own reasons are reached:
// NotAllowedByListeners, where a listener matches the name and turns
// the route away, either refusing its namespace or, for an HTTPRoute
// pinning a passthrough listener, being unable to serve its kind; and
// NoMatchingParent, for a sectionName naming a passthrough listener
// this Gateway does not render, which is what Gateway API calls a
// parentRef whose port or section matches no listener. The rest land on
// NoMatchingListenerHostname, which is where the residue goes rather
// than a shape in its own right; the shapes are enumerated on the
// withdrawalCause constants, so a cause added later cannot slip past a
// list here that nobody updated. Reading that reason as the absence of
// a listener is wrong for most of what reaches it: a passthrough
// listener answers the SNI and, in the port-443 form, admits routes
// from every namespace attached to this Gateway, and a listener a route
// pins by the wrong sectionName or the wrong parentRef port is rendered
// and serving, just not to this route. Either way the route condition is the only
// object left that can say why, the listener that used to carry a
// condition of its own having gone with it.
func (r *Reconciler) updateRouteStatuses(
	ctx context.Context,
	tgw *gatewayv1alpha1.TenantGateway,
	allRefs map[routeRef]struct{},
	losers map[routeRef][]string,
	withdrawn map[routeRef][]withdrawnHostname,
) error {
	logger := log.FromContext(ctx)

	// LastTransitionTime is set by apimeta.SetStatusCondition inside
	// mergeRouteParentStatus only when the condition actually
	// transitions; building Conditions here without it keeps the
	// no-op reconcile no-op.
	for ref := range allRefs {
		lost, isLoser := losers[ref]
		gone, isWithdrawn := withdrawn[ref]
		if isLoser || isWithdrawn {
			// One route can be hit by several causes on different
			// hostnames, and Gateway API gives it a single Accepted
			// condition, so the message carries all of them rather
			// than whichever branch runs first. Only the reason has
			// to choose.
			var causes []string
			// The reason names the shape of the refusal, and the causes
			// below do not share one. Nothing rendering a listener for
			// the name is NoMatchingListenerHostname, the default here
			// and the reason a mixed set of causes settles on, because
			// a reason true of one claim misleads about the rest. A
			// race lost to another route reports HostnameConflict even
			// mixed with others, because it is the half the owner can
			// act on. A listener matching the name while refusing the
			// route's namespace is NotAllowedByListeners, which is
			// what Gateway API calls that case, and only when it is
			// the whole story.
			reason := string(gatewayv1.RouteReasonNoMatchingListenerHostname)
			if isLoser {
				// Sorted for the same reason describeWithdrawn sorts:
				// the hostnames come out of a map, and a message that
				// reorders between passes rewrites the condition, which
				// writes status, which requeues this object through the
				// route watch.
				sort.Strings(lost)
				// Compacted for the same reason describeWithdrawn
				// compacts: spec.hostnames is a plain array, so one
				// route may list a name twice, and the message would
				// then say it twice.
				causes = append(causes, fmt.Sprintf("hostname(s) %s already claimed by another route", strings.Join(slices.Compact(lost), ", ")))
				reason = "HostnameConflict"
			}
			if isWithdrawn {
				desc := describeWithdrawn(gone)
				if desc.absentSection != "" {
					causes = append(causes, fmt.Sprintf("hostname(s) %s pinned by sectionName to a TLS-passthrough listener this Gateway does not render", desc.absentSection))
				}
				if desc.refusedKind != "" {
					causes = append(causes, fmt.Sprintf("hostname(s) %s pinned by sectionName to a TLS-passthrough listener, which terminates nothing, so no HTTPRoute is served through it", desc.refusedKind))
				}
				if desc.mismatched != "" {
					causes = append(causes, fmt.Sprintf("hostname(s) %s not served through the sectionName this route names, which answers a different hostname", desc.mismatched))
				}
				if desc.wrongPort != "" {
					causes = append(causes, fmt.Sprintf("hostname(s) %s not served through the parentRef port this route names, which no listener answering them is published on", desc.wrongPort))
				}
				if desc.answered != "" {
					causes = append(causes, fmt.Sprintf("hostname(s) %s answered by a TLS-passthrough listener, so no HTTPS listener is rendered for them", desc.answered))
				}
				if desc.unserved != "" {
					causes = append(causes, fmt.Sprintf("hostname(s) %s claimed only by a TLSRoute, which needs a passthrough listener this Gateway does not declare", desc.unserved))
				}
				if desc.foreign != "" {
					causes = append(causes, fmt.Sprintf("hostname(s) %s served by a native-port listener that admits routes from namespace %s only", desc.foreign, tgw.Namespace))
					// Counted rather than enumerated: every other cause
					// has already appended by here, so one entry means
					// the refusal is the whole story, and a cause added
					// later cannot slip past a list nobody updated.
					if len(causes) == 1 {
						reason = string(gatewayv1.RouteReasonNotAllowedByListeners)
					}
				}
				// Checked after every append rather than beside its
				// own, for the reason the count above is a count: this
				// reason is true only when the missing section is the
				// whole story, and the appends do not run in a fixed
				// order relative to each other.
				if desc.absentSection != "" && len(causes) == 1 {
					reason = string(gatewayv1.RouteReasonNoMatchingParent)
				}
				// Same shape as the namespace refusal and the same
				// reason: a listener answers the name and turns this
				// route away. One sectionName cannot name both a
				// rendered passthrough listener and no listener, so
				// this and the check above never fire on one route.
				if desc.refusedKind != "" && len(causes) == 1 {
					reason = string(gatewayv1.RouteReasonNotAllowedByListeners)
				}
			}
			if err := r.updateRouteParentStatus(ctx, ref, []metav1.Condition{
				{
					Type:    "Accepted",
					Status:  metav1.ConditionFalse,
					Reason:  reason,
					Message: fmt.Sprintf("On TenantGateway %s/%s: %s", tgw.Namespace, tgw.Name, strings.Join(causes, "; ")),
				},
			}); err != nil {
				logger.Error(err, "update unserved route status", "route", ref.namespace+"/"+ref.name)
			}
			continue
		}
		if err := r.updateRouteParentStatus(ctx, ref, []metav1.Condition{
			{
				Type:    "Accepted",
				Status:  metav1.ConditionTrue,
				Reason:  "Accepted",
				Message: fmt.Sprintf("Route attached to TenantGateway %s/%s", tgw.Namespace, tgw.Name),
			},
		}); err != nil {
			logger.Error(err, "update winner route status", "route", ref.namespace+"/"+ref.name)
		}
	}
	return nil
}

// reconcileTLSRouteWithdrawal keeps this controller's Accepted condition
// on attached TLSRoutes honest in the modes where updateRouteStatuses
// above says nothing. collectHostnameClaims returns no claims for a
// whole-apex mode, so that pass runs over an empty ref set and neither
// writes nor retracts anything.
//
// Edge renders no TLS-passthrough listener, so every attached TLSRoute
// pins a section that is gone and is told so. NoMatchingParent is
// Gateway API's reason for a parentRef whose port or sectionName
// matches no listener on the Gateway, which is what the platform's own
// api, vm-exportproxy and cdi-uploadproxy routes now have: all three
// pin sectionName tls-<svc>.
//
// The other whole-apex modes render those listeners and serve them, but
// this controller collects no claims there and so has no basis to judge
// any TLSRoute. It therefore owns no condition on them, and drops the
// one it wrote while the tenant ran edge. Leaving that behind inverts
// the problem the withdrawal exists for: a served endpoint reported as
// matching no parent, with a message naming a class provider that no
// longer terminates anything.
//
// HTTP-01 is not handled here at all: it collects claims, so
// updateRouteStatuses has already judged every route this pass would
// have anything to say about.
//
// Both directions skip a route that declares no hostnames. Under
// HTTP-01 such a route is judged on the hostname the listener it
// selects lends it, but that substitution needs a rendered passthrough
// listener, and these modes are exactly the ones where the route's
// sectionName may name none. A refusal written here would then have no
// path back: the HTTP-01 pass judges only routes that produced a claim,
// so a route pinned to a section it renders no listener for would carry
// an edge refusal after the tenant moved off edge.
func (r *Reconciler) reconcileTLSRouteWithdrawal(ctx context.Context, tgw *gatewayv1alpha1.TenantGateway) error {
	if !servesWholeApex(tgw) {
		return nil
	}
	withdraw := !rendersTLSPassthrough(tgw)
	logger := log.FromContext(ctx)

	allowed, err := r.allowedAttachNamespaces(ctx, tgw)
	if err != nil {
		return err
	}
	routes := &gatewayv1alpha2.TLSRouteList{}
	if err := r.List(ctx, routes); err != nil {
		return fmt.Errorf("list TLSRoutes: %w", err)
	}
	for i := range routes.Items {
		route := &routes.Items[i]
		if _, ok := allowed[route.Namespace]; !ok {
			continue
		}
		if len(route.Spec.Hostnames) == 0 {
			continue
		}
		for _, parentRef := range allAttachingParentRefs(route.Spec.ParentRefs, route.Namespace, tgw) {
			ref := routeRef{
				kind:      routeKindTLS,
				namespace: route.Namespace,
				name:      route.Name,
				parentRef: parentRef,
			}
			var err error
			if withdraw {
				err = r.updateRouteParentStatus(ctx, ref, []metav1.Condition{
					{
						Type:    "Accepted",
						Status:  metav1.ConditionFalse,
						Reason:  "NoMatchingParent",
						Message: fmt.Sprintf("TenantGateway %s/%s terminates TLS at its class provider and renders no TLS-passthrough listener", tgw.Namespace, tgw.Name),
					},
				})
			} else {
				err = r.dropTLSRouteParentStatus(ctx, ref)
			}
			if err != nil {
				logger.Error(err, "reconcile TLSRoute status", "route", ref.namespace+"/"+ref.name)
			}
		}
	}
	return nil
}

// dropTLSRouteParentStatus removes this controller's RouteParentStatus
// entry for ref from a TLSRoute, leaving every other controller's entry
// in place. Same idempotency contract as updateRouteParentStatus: the
// Status().Update is issued only when the entry was actually there.
func (r *Reconciler) dropTLSRouteParentStatus(ctx context.Context, ref routeRef) error {
	route := &gatewayv1alpha2.TLSRoute{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: ref.namespace, Name: ref.name}, route); err != nil {
		return fmt.Errorf("get TLSRoute: %w", err)
	}
	before := route.DeepCopy()
	removeRouteParentStatus(&route.Status.Parents, ref.parentRef)
	if routeParentStatusEqual(before.Status.Parents, route.Status.Parents) {
		return nil
	}
	return r.Status().Update(ctx, route)
}

// removeRouteParentStatus deletes the entry tagged with (ControllerName,
// ref), the exact key mergeRouteParentStatus writes under.
func removeRouteParentStatus(parents *[]gatewayv1.RouteParentStatus, ref gatewayv1.ParentReference) {
	kept := (*parents)[:0]
	for _, ps := range *parents {
		if ps.ControllerName == ControllerName && parentRefEqual(ps.ParentRef, ref) {
			continue
		}
		kept = append(kept, ps)
	}
	*parents = kept
}

// updateRouteParentStatus locates or creates the RouteParentStatus
// entry for our ControllerName on the given route (HTTPRoute or
// TLSRoute, by ref.kind) and merges Conditions in.
//
// Idempotency contract: Status().Update() is only issued when the
// merge actually changes something. apimeta.SetStatusCondition
// preserves LastTransitionTime when Type/Status/Reason/Message all
// match the existing entry, so a quiescent reconcile produces no
// resource-version bump and the Owns/Watches re-trigger storm
// short-circuits at the controller-runtime workqueue level.
func (r *Reconciler) updateRouteParentStatus(ctx context.Context, ref routeRef, conds []metav1.Condition) error {
	switch ref.kind {
	case routeKindHTTP:
		route := &gatewayv1.HTTPRoute{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: ref.namespace, Name: ref.name}, route); err != nil {
			return fmt.Errorf("get HTTPRoute: %w", err)
		}
		before := route.DeepCopy()
		mergeRouteParentStatus(&route.Status.Parents, ref.parentRef, conds)
		if routeParentStatusEqual(before.Status.Parents, route.Status.Parents) {
			return nil
		}
		return r.Status().Update(ctx, route)
	case routeKindTLS:
		route := &gatewayv1alpha2.TLSRoute{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: ref.namespace, Name: ref.name}, route); err != nil {
			return fmt.Errorf("get TLSRoute: %w", err)
		}
		before := route.DeepCopy()
		mergeRouteParentStatus(&route.Status.Parents, ref.parentRef, conds)
		if routeParentStatusEqual(before.Status.Parents, route.Status.Parents) {
			return nil
		}
		return r.Status().Update(ctx, route)
	default:
		return fmt.Errorf("unknown route kind %d for %s/%s", ref.kind, ref.namespace, ref.name)
	}
}

// mergeRouteParentStatus updates or appends the RouteParentStatus
// entry tagged with (ControllerName, ParentRef), using
// apimeta.SetStatusCondition to preserve LastTransitionTime across
// no-op reconciles. Other controllers' entries (Cilium, etc.) are
// left alone.
//
// Per Gateway API, RouteParentStatus is keyed by (ParentRef,
// ControllerName) — a single route may attach via multiple parentRefs
// (e.g. one per sectionName) and each attachment owns its own status
// entry. Keying only on ControllerName would let a multi-ref route's
// later reconcile overwrite the earlier ref's status, hiding
// per-section conflicts.
func mergeRouteParentStatus(parents *[]gatewayv1.RouteParentStatus, ref gatewayv1.ParentReference, conds []metav1.Condition) {
	for i := range *parents {
		ps := &(*parents)[i]
		if ps.ControllerName != ControllerName {
			continue
		}
		if !parentRefEqual(ps.ParentRef, ref) {
			continue
		}
		for _, c := range conds {
			apimeta.SetStatusCondition(&ps.Conditions, c)
		}
		return
	}
	// First-time stamp for this (ControllerName, ParentRef) pair:
	// build the slice via SetStatusCondition so transition timestamps
	// are populated by the helper rather than hand-stamped time.Now()
	// at construction.
	newPS := gatewayv1.RouteParentStatus{
		ControllerName: ControllerName,
		ParentRef:      ref,
	}
	for _, c := range conds {
		apimeta.SetStatusCondition(&newPS.Conditions, c)
	}
	*parents = append(*parents, newPS)
}

// routeParentStatusEqual compares two RouteParentStatus slices
// ignoring observation-only fields that legitimately differ across
// reconciles (LastTransitionTime is preserved by SetStatusCondition
// when nothing else changed, but explicit comparison guards against
// drift).
func routeParentStatusEqual(a, b []gatewayv1.RouteParentStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ap, bp := a[i], b[i]
		if ap.ControllerName != bp.ControllerName {
			return false
		}
		if !parentRefEqual(ap.ParentRef, bp.ParentRef) {
			return false
		}
		if !routeConditionsEqual(ap.Conditions, bp.Conditions) {
			return false
		}
	}
	return true
}

func parentRefEqual(a, b gatewayv1.ParentReference) bool {
	return strDerefEqual(a.Group, b.Group) &&
		strDerefEqual(a.Kind, b.Kind) &&
		strDerefEqual(a.Namespace, b.Namespace) &&
		a.Name == b.Name &&
		strDerefEqual(a.SectionName, b.SectionName) &&
		port32DerefEqual(a.Port, b.Port)
}

func strDerefEqual[T ~string](a, b *T) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func port32DerefEqual(a, b *gatewayv1.PortNumber) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func routeConditionsEqual(a, b []metav1.Condition) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ac, bc := a[i], b[i]
		if ac.Type != bc.Type ||
			ac.Status != bc.Status ||
			ac.Reason != bc.Reason ||
			ac.Message != bc.Message ||
			ac.ObservedGeneration != bc.ObservedGeneration {
			return false
		}
	}
	return true
}
