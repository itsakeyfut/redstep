#!/usr/bin/env bash
# Build the redstep SQLi playground images (#47) as the local tags the lab
# references. The orchestrator pulls images by tag and does not build them, so
# this runs out of band: the CI Docker leg invokes it before the Docker-gated
# tests, and the `sqli_playground_is_exploitable` test self-skips when these tags
# are absent (so a bare runner stays green).
#
# These are deliberately vulnerable targets. They run only inside the egress-less
# lab and must never be pushed to a registry or deployed.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker build -t redstep/db:mvp  "$here/db"
docker build -t redstep/api:mvp "$here/api"
docker build -t redstep/web:mvp "$here/web"

echo "built redstep/db:mvp, redstep/api:mvp, redstep/web:mvp"
