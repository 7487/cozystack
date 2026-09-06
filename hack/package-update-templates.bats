#!/usr/bin/env bats
# -----------------------------------------------------------------------------
# Invariant for the package `update` recipes that clear templates/ wholesale.
#
# `update` refetches a package's vendored upstream manifests, and several
# recipes open by deleting templates/ to guarantee a clean slate. That is safe
# only while every file under templates/ comes back from the recipe. templates/
# is an ordinary chart directory, so a package can also keep first-party
# manifests there -- kubevirt-cdi keeps the CDI upload-proxy Ingress and
# TLSRoute -- and the recipe knows nothing about those. The wipe takes them,
# `make update` exits 0, and the loss reaches a cluster as an object that
# silently stopped being rendered at the next version bump, not as a failed
# command.
#
# The invariant: a recipe that clears templates/ must NAME every file tracked
# under it. Both halves are approximations of the shell the recipe would run,
# and each is argued at its helper below: the wipe is a text match over the
# recipe's lines rather than a parse, and "names" means the file's basename
# minus its extension appears somewhere in the Makefile -- a mention, not proof
# of a write. What that catches is the shape kubevirt-cdi had, a file the
# Makefile does not refer to at all: every recipe that clears its own
# templates/ writes each path it puts back there, so a name appearing nowhere
# in the file is a name nothing refetches. A recipe that unpacked an archive or
# globbed a stream into templates/ would produce files it never names and break
# that reading. cert-manager's `mv charts/.../crd-*.yaml` is that shape, and it
# is out of range for the separate reason below: the directory it fills belongs
# to another package.
#
# The tree is scanned rather than a list of packages pinned, so a package that
# grows its first first-party manifest under a wiping recipe of its own is
# caught by the commit that adds it. The packages that clear their own
# templates/ today refetch all of it, which is what keeps this green;
# kubevirt-cdi stopped clearing it, which is what this file was written for.
# kubevirt-cdi-operator still clears its own, and is scanned like the rest.
#
# What that leaves uncovered is a recipe clearing SOMEONE ELSE'S templates/, and
# the tree has one: packages/system/cert-manager/Makefile runs
# `rm -rf ../cert-manager-crds/templates/*` and moves the CRDs it pulled into
# that directory, while cert-manager-crds declares no update target at all. A
# first-party manifest added there is deleted by the next `make update` in
# cert-manager and nothing below reports it. Covering that means resolving the
# removal's target directory rather than reading the wiping package's own, which
# is a second helper; the pattern below is deliberately not widened to accept a
# path prefix, because that alone would fire on cert-manager and then list the
# templates of a directory it does not have -- the removal names the sibling's
# path, so the lookup has to follow it.
#
# The scan alone would also be green against a detector that finds nothing, so
# the control below runs the same two helpers over a fixture that does hold an
# unrefetched file, and over that fixture with the removal taken out.
#
# Constraints from cozytest.sh: it rewrites the closing brace of every function
# in this file into `return 0`, so a helper cannot report through its exit
# status -- both report through stdout -- and it injects `set -e`, so statuses
# are captured explicitly.
#
# Run with: hack/cozytest.sh hack/package-update-templates.bats
# -----------------------------------------------------------------------------

# Prints the recipe line that clears templates/ wholesale, for a package
# Makefile whose `update` target has one. Silent otherwise, including for a
# Makefile with no `update` target at all.
#
# The recipe is read as the run of tab-indented lines after `update:`. make also
# ignores blank lines inside a recipe and this stops at the first one, so such a
# recipe would be read short; none in the tree is written that way.
#
# The match accepts `rm -rf`, `rm -fr` and `rm -r` against `templates` and
# `./templates`, bare, with a trailing slash, or with a `/*` glob -- the three
# spellings that empty the directory. It deliberately does not accept
# `rm -rf templates/one-file.yml`, which takes a single file the recipe goes on
# to refetch (rabbitmq-operator), nor a narrower glob such as
# `rm -rf templates/*.yaml`, which takes a subset the same way.
#
# It is a text match and not a shell parse, so a quoted `rm -rf "templates"`, a
# removal reached through a variable, a `find -delete` and a `cd` into another
# directory first are all invisible to it, as is a path-prefixed target -- the
# cert-manager case in the header is one, and the prefix is the only thing
# keeping it out: the `/*` it ends with is accepted. The enumeration is only as
# complete as the last reader made it, so extend it in the same edit as the
# pattern.
wipe_command() {
    awk '/^update:/ { r = 1; next } r && /^\t/ { print; next } r { exit }' "$1" |
        grep -E 'rm[[:space:]]+-(rf|fr|r)[[:space:]]+(\./)?templates(/\*?)?([[:space:]]|;|&|$)' || true
}

# Prints every file tracked under a package's templates/ that its Makefile
# never mentions, one path per line. Whether that matters is the caller's call:
# it matters for a package whose recipe clears the directory, and for no other.
#
# The listing is the index, so only a tracked file is at stake -- it is the one
# the next `make update` deletes out from under a reviewer who has no reason to
# look. Reading the working tree instead would fail a package over the
# developer's own litter: an untracked .orig from a hand-applied patch, a
# half-written template, a .DS_Store. A guard that goes red on scratch files is
# a guard that gets switched off.
#
# The extension is stripped before matching, because a recipe may assemble the
# filename from a variable holding the bare stem -- etcd-operator-crds writes
# templates/$$c.yaml from a CRDS list of names without one. A basename whose
# only dot is its first character keeps the whole name instead: stripping there
# leaves the empty string, which grep matches against every Makefile, and the
# file would pass without being looked at. The search covers the whole Makefile
# rather than the recipe alone for the same reason as the stem: the variable is
# assigned above the target. Both make the match generous, so a stem that
# appears for an unrelated reason satisfies it; this reports the files nothing in
# the Makefile refers to, not every file the recipe fails to write.
#
# Comment lines are dropped before the search, so a filename written into one is
# not a mention: a rationale comment above a recipe, naming the very file it is
# about, would otherwise exempt that package from its own guard. Comments
# naming a template are not rare in the tree, so this is the difference between
# a package being read and a package being taken at its word.
#
# The NAME and NAMESPACE assignments go the same way. They are the package's
# identity rather than a reference to any file, and a package called foo-bar
# whose recipe writes templates/bar.yaml has that file's stem inside its own
# name: left in, they let a package vouch for its own templates without any
# recipe touching them. The match is on the variable name rather than on one
# way of writing the assignment, because the hole does not care how it was
# spelled: `export` is optional, whitespace either side of the operator is
# optional, and make's assignment forms (`=`, `:=`, `::=`, `?=`, `+=`) are all
# accepted. The tree uses at least three of these -- `export NAME=`, the bare
# `NAME=`, and `NAME := ` in packages/core/testing -- and pinning the list of
# spellings is what this deliberately avoids. Two names are named rather than a
# `[A-Z_]+=` shape for the opposite reason: a variable holding content is what
# the whole-file search is there to find, and etcd-operator-crds names its
# templates through nothing but its CRDS list, so a shape that broad would be
# one unspaced assignment away from blinding the scan to five CRDs. That list
# is written spaced, which is why the broader pattern would not reach it today
# and why no case below can pin this choice; two names cannot reach it at any
# spacing. Precautionary like the comment strip above: no package the scan
# reaches is exempted this way today, and the line is what keeps the first one
# that tries from being.
unnamed_templates() {
    _mk=$1
    _dir=$(dirname "$_mk")
    _code=$(grep -vE '^([[:space:]]*@?#|(export[[:space:]]+)?(NAME|NAMESPACE)[[:space:]]*[:?+]*=)' "$_mk") || true
    git -C "$_dir" ls-files -- templates | while IFS= read -r _f; do
        _base=${_f##*/}
        _stem=${_base%.*}
        [ -n "$_stem" ] || _stem=$_base
        printf '%s\n' "$_code" | grep -Fq -- "$_stem" || printf '%s\n' "$_dir/$_f"
    done
}

@test "no package update recipe clears templates/ over a file it never refetches" {
    examined=0
    offenders=""

    for mk in packages/*/*/Makefile; do
        [ -f "$mk" ] || continue
        examined=$((examined + 1))
        [ -n "$(wipe_command "$mk")" ] || continue
        found=$(unnamed_templates "$mk")
        if [ -n "$found" ]; then
            offenders="$offenders
$mk clears templates/ but names none of:
$found"
        fi
    done

    # A glob that matched nothing -- packages/ moved, or the suite run from
    # somewhere other than the repository root -- would otherwise report success
    # having looked at no Makefile at all.
    if [ "$examined" -eq 0 ]; then
        echo "no packages/*/*/Makefile found: run this from the repository root" >&2
        exit 1
    fi

    # The index is where the scan reads a package's templates from, so an answer
    # of nothing here means it could not have reported anything either.
    if [ -z "$(git ls-files -- packages | head -1)" ]; then
        echo "git ls-files reported no tracked file under packages/: this test" >&2
        echo "cannot see a template directory, so it measured nothing" >&2
        exit 1
    fi

    if [ -n "$offenders" ]; then
        echo "a package update recipe deletes templates/ over a file it does not refetch:" >&2
        echo "$offenders" >&2
        echo "" >&2
        echo "templates/ holds first-party manifests alongside the vendored ones and" >&2
        echo "'rm -rf templates' takes both, silently: the next 'make update' drops the" >&2
        echo "first-party ones and still exits 0. Either keep 'mkdir -p templates'" >&2
        echo "without the removal -- wget -O and kustomize > overwrite what they fetch" >&2
        echo "anyway -- or write the local file from the recipe too, where the clean" >&2
        echo "slate is load-bearing (etcd-operator-crds stages into a tmpdir first)." >&2
        exit 1
    fi
}

@test "the scan reports a template file that a wiping recipe does not name" {
    # Negative control. The test above passes on a tree with no offender and on
    # a detector that cannot see one; this separates the two by handing the same
    # helpers a package that is broken in exactly the way kubevirt-cdi was.
    tmp=$(mktemp -d)
    mkdir -p "$tmp/pkg/templates"
    : > "$tmp/pkg/templates/fetched.yaml"
    : > "$tmp/pkg/templates/local-extra.yaml"
    # A tracked dotfile. Stripping its extension leaves nothing and an empty
    # pattern matches every Makefile, so without the guard in the helper this
    # file is skipped in silence rather than reported.
    : > "$tmp/pkg/templates/.gitkeep"
    # Two files whose stems sit inside the package's own identity, the shape
    # every `foo-bar` package writing templates/bar.yaml has. One is covered by
    # NAME and one by NAMESPACE, and the Makefile below writes the first as
    # `export NAME=` and the second as `NAMESPACE := `, so between them the
    # export prefix, the bare form, spacing around the operator and the `:=`
    # spelling are all exercised. Left in the search, each of these matches
    # with nothing writing it.
    : > "$tmp/pkg/templates/name-echo.yaml"
    : > "$tmp/pkg/templates/bare-echo.yaml"
    # The comment names the file the recipe does not write, which is what a
    # rationale comment above a real recipe looks like. It must not count as the
    # recipe naming it.
    printf 'export NAME=demo-name-echo\nNAMESPACE := cozy-bare-echo\n# local-extra.yaml is written by hand\nupdate:\n\trm -rf templates\n\tmkdir templates\n\twget -O templates/fetched.yaml https://example.invalid/f.yaml\n' \
        > "$tmp/pkg/Makefile"
    # An index is what the helper reads, so the fixture needs one. Staged rather
    # than committed: nothing here needs a commit object, and a commit would want
    # an identity and a signature from whoever runs the suite.
    git -C "$tmp" init --quiet
    git -C "$tmp" add --all

    # Untracked litter, written after the staging so it stays untracked. Neither
    # file is at stake and neither may be reported.
    : > "$tmp/pkg/templates/scratch.yaml"
    : > "$tmp/pkg/templates/.DS_Store"

    if [ -z "$(wipe_command "$tmp/pkg/Makefile")" ]; then
        echo "the matcher did not see 'rm -rf templates' in the fixture recipe" >&2
        rm -rf "$tmp"
        exit 1
    fi

    # Exactly the tracked files the recipe does not name. Reporting the fetched
    # one too would fail every wiping package in the tree, reporting none of them
    # would pass all of them, and reporting the litter would fail a package over
    # a file nobody is going to miss.
    expected=$(printf '%s\n%s\n%s\n%s' "$tmp/pkg/templates/.gitkeep" "$tmp/pkg/templates/bare-echo.yaml" "$tmp/pkg/templates/local-extra.yaml" "$tmp/pkg/templates/name-echo.yaml")
    found=$(unnamed_templates "$tmp/pkg/Makefile")
    if [ "$found" != "$expected" ]; then
        echo "expected only the tracked unrefetched files to be reported:" >&2
        printf '%s\n' "$expected" >&2
        echo "got:" >&2
        printf '%s\n' "$found" >&2
        rm -rf "$tmp"
        exit 1
    fi

    # The trailing-slash spelling removes exactly as much, so it has to be seen
    # as well. Spelled with the leading ./ at the same time, which is the other
    # optional half of the pattern; the fixture above carries neither.
    printf 'update:\n\trm -rf ./templates/\n\twget -O templates/fetched.yaml https://example.invalid/f.yaml\n' \
        > "$tmp/pkg/Makefile"
    if [ -z "$(wipe_command "$tmp/pkg/Makefile")" ]; then
        echo "the matcher missed 'rm -rf ./templates/', which clears the directory" >&2
        rm -rf "$tmp"
        exit 1
    fi

    # And the glob spelling, which empties the directory without naming it as
    # the argument. It is what cert-manager's recipe writes, so it is the line a
    # package copies when it wants to clear its own templates.
    printf 'update:\n\trm -rf templates/*\n\twget -O templates/fetched.yaml https://example.invalid/f.yaml\n' \
        > "$tmp/pkg/Makefile"
    if [ -z "$(wipe_command "$tmp/pkg/Makefile")" ]; then
        echo "the matcher missed 'rm -rf templates/*', which empties the directory" >&2
        rm -rf "$tmp"
        exit 1
    fi

    # The other side of that boundary: removing one file inside templates/ is
    # rabbitmq-operator's shape, it takes only what the recipe refetches, and a
    # pattern loose enough to call it a wipe would report that package forever.
    printf 'update:\n\trm -rf templates/fetched.yaml\n\twget -O templates/fetched.yaml https://example.invalid/f.yaml\n' \
        > "$tmp/pkg/Makefile"
    if [ -n "$(wipe_command "$tmp/pkg/Makefile")" ]; then
        echo "the matcher read a single-file removal as clearing the directory" >&2
        rm -rf "$tmp"
        exit 1
    fi

    # And the shape kubevirt-cdi moved to switches the check off, so the scan
    # is measuring the removal rather than the package.
    printf 'update:\n\tmkdir -p templates\n\twget -O templates/fetched.yaml https://example.invalid/f.yaml\n' \
        > "$tmp/pkg/Makefile"
    if [ -n "$(wipe_command "$tmp/pkg/Makefile")" ]; then
        echo "the matcher fired on a recipe that only creates the directory" >&2
        rm -rf "$tmp"
        exit 1
    fi

    rm -rf "$tmp"
}
