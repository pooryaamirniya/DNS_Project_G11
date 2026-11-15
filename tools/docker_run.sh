#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker build -t patchguard-security-project:local .
# Root filesystem remains read-only. Writable paths are restricted to the bind mount and tmpfs.
# Non-root container execution ensures no root-owned output on the host.
mkdir -p artifacts/ci
chmod -R u+rwX artifacts/ci
set +e
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 128 --memory 768m --cpus 2 --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/work:rw" patchguard-security-project:local \
  --out artifacts/ci \
  --config configs/frame-correct.json \
  --config configs/frame-incomplete.json \
  --config configs/frame-regression.json \
  --config configs/cjsonreal-correct.json \
  --config configs/cjsonreal-incomplete.json \
  --config configs/cjsonreal-regression.json
status=$?
set -e
# Intentional negative fixtures return 10/20; CI asserts each expected scenario verdict
# rather than treating the full negative-test batch's status as a failed pipeline.
project_dir="$PWD"
(cd /tmp && python3 "$project_dir/tools/assert_matrix.py" "$project_dir/artifacts/ci/report.json")
exit $?
