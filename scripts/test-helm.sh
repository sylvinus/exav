#!/usr/bin/env bash
# Render-check the Helm chart in deploy/helm/exav-chart.
#
# WHY: `helm lint` reports a template `fail` as INFO and exits 0, so the render
# guards the chart depends on (no signature source, forbidden env vars) only
# show up under `helm template`. The hardening settings are asserted on the
# rendered output so that a values change cannot drop them in silence.
#
# USAGE: scripts/test-helm.sh
# REQUIREMENTS: helm on PATH. No cluster is needed.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
chart=deploy/helm/exav-chart

if ! command -v helm >/dev/null 2>&1; then
  echo "error: helm not found. Install helm to check the chart." >&2
  exit 1
fi

if helm template exav "$chart" > /dev/null 2>&1; then
  echo "helm template succeeded with no signature source; it must fail by default" >&2
  exit 1
fi

guard=$(helm template exav "$chart" -f "$chart/ci/allow-no-db-values.yaml" \
  --set 'extraEnv[0].name=EXAV_ALLOW_SHUTDOWN' --set 'extraEnv[0].value=1' 2>&1 || true)
if ! grep -q 'extraEnv must not set' <<< "$guard"; then
  echo "helm template must fail with the extraEnv guard when EXAV_ALLOW_SHUTDOWN is set" >&2
  exit 1
fi

for f in "$chart"/ci/*-values.yaml; do
  echo "== $f"
  helm lint --strict "$chart" -f "$f"
  rendered=$(helm template exav "$chart" -f "$f")

  for want in 'readOnlyRootFilesystem: true' 'runAsUser: 65532' \
    'automountServiceAccountToken: false' 'seccompProfile'; do
    if ! grep -q -- "$want" <<< "$rendered"; then
      echo "rendered manifest is missing expected setting: $want" >&2
      exit 1
    fi
  done

  for forbid in EXAV_ALLOW_SHUTDOWN EXAV_ALLOW_HTTP_SCAN; do
    if grep -q -- "$forbid" <<< "$rendered"; then
      echo "rendered manifest must not set: $forbid" >&2
      exit 1
    fi
  done
done

dist=$(mktemp -d)
trap 'rm -rf "$dist"' EXIT
helm package "$chart" --version 0.0.0-ci --app-version 0.0.0-ci -d "$dist" > /dev/null
if tar tzf "$dist/exav-chart-0.0.0-ci.tgz" | grep -q '/ci/'; then
  echo "the packaged chart must not contain ci/ values files" >&2
  exit 1
fi

echo "helm chart checks passed"
