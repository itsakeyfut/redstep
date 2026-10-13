#!/usr/bin/env bash
# Build the redstep SQLi playground images (#47) as the local tags the lab
# references. The orchestrator pulls images by tag and does not build them, so
# this runs out of band, by hand. Run it before the Docker-gated tests to
# exercise the SQLi end to end; without it `sqli_playground_is_exploitable`
# self-skips (so a bare runner, and CI as it currently stands, stay green but do
# NOT exercise the exploit). Wiring this into a CI Docker leg is not done yet.
#
# These are deliberately vulnerable targets. They run only inside the egress-less
# lab and must never be pushed to a registry or deployed.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker build -t redstep/db:mvp  "$here/db"
docker build -t redstep/api:mvp "$here/api"
docker build -t redstep/web:mvp "$here/web"

echo "built redstep/db:mvp, redstep/api:mvp, redstep/web:mvp"
