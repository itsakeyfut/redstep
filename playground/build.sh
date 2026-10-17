#!/usr/bin/env bash
# Build the redstep SQLi playground images (#47) as the local tags the lab
# references. The orchestrator pulls images by tag and does not build them, so
# this runs out of band. Run it before the Docker-gated tests to exercise the
# SQLi end to end; without it `sqli_playground_is_exploitable` self-skips (so a
# bare runner stays green but does NOT exercise the exploit). The CI `playground`
# leg runs this on the Linux runner so the exploit is exercised in CI too (#52).
#
# These are deliberately vulnerable targets. They run only inside the egress-less
# lab and must never be pushed to a registry or deployed.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker build -t redstep/db:mvp  "$here/db"
docker build -t redstep/api:mvp "$here/api"
docker build -t redstep/web:mvp "$here/web"
# The SSRF canary (#65): an out-of-band witness point the coerced api reaches over
# the lab network; the orchestrator reads its logs to witness the callback.
docker build -t redstep/canary:mvp "$here/canary"
# The patched api variant (#54, #63, #64, #65): same crate, the `fixed` feature
# parameterizes the vulnerable handlers. The attack-to-defense loops replay the
# same probes against it.
docker build -t redstep/api:fixed --build-arg FEATURES=fixed "$here/api"

echo "built redstep/db:mvp, redstep/api:mvp, redstep/api:fixed, redstep/web:mvp, redstep/canary:mvp"
