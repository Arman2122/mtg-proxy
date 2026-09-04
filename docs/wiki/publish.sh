#!/usr/bin/env bash
#
# Publish docs/wiki/ to the GitHub wiki.
#
# The wiki is a separate git repository. This clones it into a temporary
# directory, replaces its pages with the ones here, and pushes -- so the
# repository stays the source and the wiki stays a copy.
#
# GitHub creates that repository the first time a page is saved through the web
# interface, and there is no API for it. If this script tells you the wiki does
# not exist yet, open the wiki, click "Create the first page", save anything at
# all, and run it again.

set -euo pipefail

REPO_SLUG="${MTG_WIKI_REPO:-Arman2122/mtg-proxy}"
WIKI_URL="https://github.com/${REPO_SLUG}.wiki.git"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { printf 'publish: %s\n' "$1" >&2; exit 1; }

pages=("${here}"/*.md)
[ -e "${pages[0]}" ] || die "no pages found in ${here}"

if ! git ls-remote "${WIKI_URL}" >/dev/null 2>&1; then
  cat >&2 <<NOTE
publish: the wiki repository does not exist yet.

GitHub creates it the first time a page is saved through the web interface, and
offers no API for it. One manual step, once:

  1. open https://github.com/${REPO_SLUG}/wiki
  2. click "Create the first page", then "Save page"
     (the content does not matter -- this script overwrites it)

Then run this again. Every publish after that needs nothing manual.
NOTE
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

echo "==> cloning ${WIKI_URL}"
git clone --quiet --depth 1 "${WIKI_URL}" "${work}/wiki"

# Delete the wiki's current pages before copying, so a page removed here is
# removed there. Anything not tracked by git is left alone.
( cd "${work}/wiki" && git rm --quiet -r --ignore-unmatch '*.md' )

# README.md and publish.sh document the publishing process itself; they belong
# in the repository, not on the wiki.
for page in "${pages[@]}"; do
  name="$(basename "${page}")"
  [ "${name}" = "README.md" ] && continue
  cp "${page}" "${work}/wiki/${name}"
done

cd "${work}/wiki"
git add -A

if git diff --cached --quiet; then
  echo "==> the wiki already matches; nothing to publish"
  exit 0
fi

echo "==> publishing"
git diff --cached --name-status

source_rev="$(git -C "${here}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
git commit --quiet -m "docs: sync the wiki from the repository at ${source_rev}"
git push --quiet origin HEAD

echo "==> done: https://github.com/${REPO_SLUG}/wiki"
