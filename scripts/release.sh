#!/usr/bin/env sh
#
# Tag a release and start the GitHub release workflow.
#
#   scripts/release.sh 0.1.0
#
# Tags the current commit as vX.Y.Z, pushes the tag, and dispatches the release
# workflow *at that tag* rather than relying on the push to trigger it. The
# direct dispatch is the reliable path here: a plain `git push` over a flaky link
# can drop the connection after the objects land but before the ref does, and a
# tag push that arrives without a matching workflow trigger leaves a tag with no
# release behind it.
#
# Needs the `gh` CLI, authenticated with permission to write to the repository.
set -eu

if [ $# -ne 1 ]; then
    echo "usage: $0 <version>            e.g. $0 0.1.0" >&2
    exit 2
fi

version="${1#v}"
tag="v${version}"

case "$version" in
    *[!0-9.]* | "" | .* | *.)
        echo "$0: '$1' does not look like a version (expected X.Y.Z)" >&2
        exit 2
        ;;
esac

cargo_version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
if [ "$cargo_version" != "$version" ]; then
    echo "$0: Cargo.toml says $cargo_version but the tag would be $tag" >&2
    echo "     bump the version in Cargo.toml first" >&2
    exit 1
fi

# The changelog is the release body, so an unedited "unreleased" section would
# ship as one.
if ! grep -q "^## ${version}" CHANGELOG.md; then
    echo "$0: CHANGELOG.md has no '## ${version}' section" >&2
    exit 1
fi

command -v gh >/dev/null || {
    echo "$0: the gh CLI is required (https://cli.github.com)" >&2
    exit 1
}

if [ -n "$(git status --porcelain)" ]; then
    echo "$0: the working tree is dirty; commit first" >&2
    exit 1
fi

if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    echo "$0: tag $tag already exists" >&2
    exit 1
fi

branch=$(git rev-parse --abbrev-ref HEAD)
echo "==> tagging $tag on $branch ($(git rev-parse --short HEAD))"
git tag -a "$tag" -m "Release $tag"
git push origin "$tag"

echo "==> dispatching the release workflow for $tag"
gh workflow run release.yml --ref "$tag" -f "tag=$tag"

echo "==> waiting for the run to appear"
sleep 5
gh run list --workflow=release.yml --limit 3

cat <<EOF

Follow it with:
  gh run watch
or in the browser:
  gh run view --web
EOF
