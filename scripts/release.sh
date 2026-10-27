#!/usr/bin/env bash
# Build, label and push the Docker Hub image, then sync the Hub overview.
#
# Usage: scripts/release.sh <tag>          e.g. scripts/release.sh auto-blocklist-v9
#
# The overview sync (DOCKERHUB.md -> Hub "Overview") runs only when
# DOCKERHUB_TOKEN is set to a Docker Hub personal access token with
# Read, Write, Delete scope (Read/Write alone gets a 403). Set DOCKERHUB_ONLY_DESCRIPTION=1 to skip build/push.
set -euo pipefail

IMAGE=cechode/caddy-defender
HUB_USER=cechode
REPO_URL=https://github.com/chunkychode/caddy-defender
BRANCH=auto-blocklist
SHORT_DESC="Caddy + caddy-defender with automatic scanner blocklisting (auto-blocklist fork)"

TAG=${1:?usage: scripts/release.sh <tag>}
cd "$(dirname "$0")/.."

if [[ -z "${DOCKERHUB_ONLY_DESCRIPTION:-}" ]]; then
	if [[ -n "$(git status --porcelain)" ]]; then
		echo "warning: working tree is dirty; revision label will not match the image contents" >&2
	fi
	REV=$(git rev-parse HEAD)

	MSYS_NO_PATHCONV=1 docker build \
		--label "org.opencontainers.image.title=caddy-defender" \
		--label "org.opencontainers.image.vendor=$HUB_USER" \
		--label "org.opencontainers.image.documentation=$REPO_URL/blob/$BRANCH/README.md" \
		--label "org.opencontainers.image.source=$REPO_URL" \
		--label "org.opencontainers.image.url=$REPO_URL/tree/$BRANCH" \
		--label "org.opencontainers.image.revision=$REV" \
		--label "org.opencontainers.image.version=$TAG" \
		--label "org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		--label "org.opencontainers.image.description=$SHORT_DESC" \
		--label "org.opencontainers.image.licenses=MIT" \
		-t "$IMAGE:$TAG" -t "$IMAGE:latest" .

	docker push "$IMAGE:$TAG"
	docker push "$IMAGE:latest"
fi

if [[ -z "${DOCKERHUB_TOKEN:-}" ]]; then
	echo "DOCKERHUB_TOKEN not set; skipping Hub overview sync"
	exit 0
fi

LOGIN=$(python -c 'import json,sys; print(json.dumps({"username":sys.argv[1],"password":sys.argv[2]}))' "$HUB_USER" "$DOCKERHUB_TOKEN" |
	curl -sS -w '\n%{http_code}' -H "Content-Type: application/json" -d @- https://hub.docker.com/v2/users/login)
if [[ "${LOGIN##*$'\n'}" != 200 ]]; then
	echo "Hub login failed (HTTP ${LOGIN##*$'\n'}): ${LOGIN%$'\n'*}" >&2
	exit 1
fi
JWT=$(python -c 'import json,sys; print(json.load(sys.stdin)["token"])' <<<"${LOGIN%$'\n'*}")

PATCH=$(python -c 'import json,sys; print(json.dumps({"description":sys.argv[1],"full_description":open("DOCKERHUB.md",encoding="utf-8").read()}))' "$SHORT_DESC" |
	curl -sS -w '\n%{http_code}' -X PATCH -H "Authorization: JWT $JWT" -H "Content-Type: application/json" -d @- \
		"https://hub.docker.com/v2/repositories/$IMAGE/")
if [[ "${PATCH##*$'\n'}" != 200 ]]; then
	echo "Hub overview update failed (HTTP ${PATCH##*$'\n'}): ${PATCH%$'\n'*}" >&2
	echo "Updating the overview needs a PAT with Read, Write, Delete scope." >&2
	exit 1
fi

echo "Hub overview updated: https://hub.docker.com/r/$IMAGE"
