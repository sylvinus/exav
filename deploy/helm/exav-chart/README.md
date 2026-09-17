# exav Helm chart

This chart installs [exav](https://exav.org), a clamd- and ICAP-compatible
malware scanner, on Kubernetes. It creates a Deployment, a ClusterIP
Service, a Secret, and a ServiceAccount. The chart creates no Ingress and no
Gateway route, because clamd and ICAP are raw TCP protocols without TLS or
authentication. Each resource takes the release name when the release name
contains `exav`, otherwise it takes `<release>-exav`. The Secret exists only
when you set `signatures.sources` or `signatures.dbUrl`. The chart applies a
hardened Pod Security Standard by default. The chart ships with no
signature source: you must set one before the daemon can serve scans.

## Install

### Install from OCI

```sh
helm install exav oci://ghcr.io/sylvinus/exav-chart --version <X.Y.Z> \
  --set 'signatures.sources={https://mirror.example/db/}'
```

Replace `<X.Y.Z>` with a released chart version. See
[Upgrades and versioning](#upgrades-and-versioning) below for how the chart
version, the app version, and the image tag relate.

### Install from a checkout

```sh
helm install exav deploy/helm/exav-chart \
  --set image.tag=<X.Y.Z> \
  --set 'signatures.sources={https://mirror.example/db/}'
```

`Chart.yaml` in a checkout holds version `0.0.0`. Set `image.tag` to a real
released image tag yourself. Without it, the pod pulls image tag `0.0.0`,
which does not exist.

## Install check

To test an install, forward the Service port in one terminal:

```sh
kubectl port-forward svc/exav 3310:3310
```

In another terminal, send a `PING` and run a scan:

```sh
printf 'PING\n' | nc 127.0.0.1 3310                          # answers PONG
exav --ping --connect clamd://127.0.0.1:3310
exav --connect clamd://127.0.0.1:3310 --send-as contents file.bin
```

`clamdscan` has no host flag. Point it at the forwarded port with a config
file instead:

```sh
clamdscan --stream \
  --config-file=<(printf 'TCPAddr 127.0.0.1\nTCPSocket 3310\n') file.bin
```

## Signature sources

exav ships with no signature database and no default mirror. Set one of
`signatures.sources`, `signatures.dbUrl`, or `signatures.existingSecret`. For
a test install only, set `signatures.allowNoDb` to `true` instead.

`signatures.sources` is a list of CVD mirror bases or exact feed URLs. A URL
that ends in `/` is a mirror base; exav expands it to `main.cvd`,
`daily.cvd`, and `bytecode.cvd`. This is a raw load: it takes about 75
seconds and uses about 5.6 GiB of RAM per replica. exav re-checks for a new
file with a full fetch every 86400 seconds by default
(`signatures.updateIntervalSecs`).

`signatures.dbUrl` points at a prebuilt `.exavdb` file built elsewhere. This
load takes about 3.5 seconds and uses about 1.2 GiB of RAM. exav re-checks
the URL with a cheap conditional HEAD request every 300 seconds by default
(`signatures.updateIntervalSecs`).

`signatures.updateIntervalSecs` sets both cadences. exav floors the value at
60 seconds. Updates cannot be turned off.

The figures 75 s / 5.6 GiB and 3.5 s / 1.2 GiB are approximate measurements
from the [prebuilt database guide](https://exav.org/guides/prebuilt-database/).
The ratio between the two matters more than the exact numbers.

Both URLs can carry credentials, as `user:pass@host/path` or as a token in
the path. The chart stores both values in a Secret, never in a ConfigMap or
in a plain environment variable. The chart-managed Secret holds the keys
`sig-sources` and `db-url`; omit a key you do not use. Set
`signatures.existingSecret` to the name of your own Secret with the same
keys to skip the chart-managed one.

`helm get values` and `helm get manifest` print the URL, and a GitOps tool
stores it in the Application spec. Only `signatures.existingSecret` keeps a
credential out of the Helm release. The chart writes a `checksum/secret` pod
annotation that is the SHA-256 of the rendered Secret, so a source change
restarts the pods. A user who can read pods can try an offline guess of a
weak password in the URL. Use `existingSecret` with a high-entropy token
when that matters. With `existingSecret`, a rotation does not restart the
pods. Run `kubectl rollout restart deployment/<name>` after a change.

Do not set `signatures.sources` or `signatures.dbUrl` together with
`signatures.existingSecret`. The chart render fails.

exav does not verify a signature on the fetched file. Point `sources` or
`dbUrl` only at a mirror you control or trust.

> **`allowNoDb` is for testing only.** With `signatures.allowNoDb: true`, the
> daemon serves with only a built-in EICAR test signature. It does not
> detect real malware. Do not use it in production. The chart render also
> fails when `allowNoDb` is true together with `sources`, `dbUrl`, or
> `existingSecret`. The chart sets the startup wait to 0 in this mode, so
> the pod becomes ready at once.

## Archive passwords

`archivePasswords.existingSecret` names a Secret that holds an archive
password list. `archivePasswords.key` names the key inside that Secret. The
file holds one password per line, byte for byte, with no trimming.

The chart mounts the file read-only at `/etc/exav/passwords/<key>` with mode
0440. This needs `podSecurityContext.fsGroup` to stay at 65532. The chart
sets `EXAV_PASSWORDS_FROM` to that path.

## Storage

`signatures.persistence.enabled: false` (the default) mounts an `emptyDir`
at `/var/lib/exav`. Each pod refetches signatures on every restart. With
more than one replica, each pod fetches on its own, which wastes bandwidth
and startup time. Prefer `signatures.dbUrl` for a fast refetch, or turn on
persistence.

`signatures.persistence.enabled: true` creates one PersistentVolumeClaim.
Set `signatures.persistence.size`, `signatures.persistence.storageClassName`
(empty string uses the cluster default class, `-` sets an empty class to
bind a pre-provisioned PV), and `signatures.persistence.accessModes`. Set
`signatures.persistence.existingClaim` to use a PVC you already made instead.
`existingClaim` needs `signatures.persistence.enabled: true`; the chart
render fails otherwise.

`replicaCount` greater than 1 with persistence on needs a `ReadWriteMany`
access mode. The chart render fails without it. Several pods must not write
the same `ReadWriteOnce` volume at the same time.

A `RollingUpdate` starts a second pod before it stops the first one, so the
node needs memory for two signature loads at once. When persistence is on
and `accessModes` lacks `ReadWriteMany`, the chart picks the `Recreate`
strategy instead: only one pod runs at a time in that case.

Some CSI drivers ignore `fsGroup`. Check that your storage class makes the
volume writable by uid 65532, the user exav runs as. Do not assume
`fsGroup` alone is enough.

### Spill

The sizes must nest: `spill.thresholdBytes` (default `16M`) inside
`spill.maxBytes` (default `2G`) inside `spill.sizeLimit`. The chart checks
the nesting at render time. A `0` or `off` value for `spill.maxBytes`
removes the per-scan cap and skips both nesting checks. Otherwise, do not
set `spill.sizeLimit` below `2Gi` unless you lower `spill.maxBytes` too.
`spill.medium: Memory` makes the spill volume a tmpfs. That tmpfs counts
against `resources.limits.memory`, so add `spill.sizeLimit` to the limit.

## Resources and workers

exav reads the pod's cgroup memory limit and sizes each worker's address
space from it. Without a memory limit, exav sizes workers from the host's
total RAM instead, and the Kubernetes OOM killer can kill the pod. Set
`resources.limits.memory` on every install.

| Signature source | Load time | RAM per replica |
|---|---|---|
| Raw sources (`signatures.sources`) | ~75 s | ~5.6 GiB |
| Prebuilt database (`signatures.dbUrl`) | ~3.5 s | ~1.2 GiB |

Always set `resources.limits.memory`. Set it to about `6Gi` for raw
sources. Set it to about `3Gi` for a prebuilt database.

exav divides the memory limit among the workers. It keeps one third of the
limit for the system and subtracts the shared database. It gives each
worker the remainder, with a floor of 256 MiB. It lowers
`EXAV_MAX_PROCESS_BYTES` (`2G` by default) to that figure. Do not add
`workers x 2Gi` to the limit. Add 1 to 2 GiB of headroom for scans in
flight to the base figure.

Workers default to the number of available CPUs. This count honors a cpu
limit but not a cpu request. Set `resources.limits.cpu`, or set `workers` by
hand, on a large node.

## Startup and probes

The chart uses an exec probe, `/exav --ping`, for the startup, liveness, and
readiness probes. This checks a protocol answer, not only a TCP accept. A
`tcpSocket` probe would also work, because the socket opens only after
signatures finish loading.

`probes.startup.failureThreshold` defaults to a computed value: the ceiling
of `(wait + 600) / periodSeconds`. With the default 10-second period, this
is 240 checks, about 40 minutes. The chart budgets the 1800-second wait in
every mode as a safety margin for a slow mirror, plus 600 seconds for the
fetch and the first load. The chart also sets the Deployment's
`progressDeadlineSeconds` to `failureThreshold * periodSeconds + 60`, so
`kubectl rollout status` waits for the full window. The threshold follows
`signatures.startupWaitSecs` when you set it. Set
`probes.startup.failureThreshold` to shorten the window.

The chart always sets `EXAV_AUTO_UPDATE=1`, so the fetch does not depend on
the image `CMD`.

`signatures.startupWaitSecs` applies only in sidecar mode: when neither
`signatures.sources` nor `signatures.dbUrl` is set. It is the time exav
waits for another container to fill `/var/lib/exav`.

A signature hot reload keeps the listener open, so it does not fail a
readiness probe. The daemon replaces the workers at once, so a scan in
flight loses its connection.

A SIGTERM stops all in-flight scans at once; the daemon does not wait for
them to finish. `terminationGracePeriodSeconds` is 30 by default. A scan
that is in progress at shutdown does not complete.

## Security posture

The chart follows the Pod Security Standard `restricted` profile by
default:

- `runAsNonRoot: true`, with uid, gid, and fsGroup set to 65532.
- All Linux capabilities dropped.
- `seccompProfile.type: RuntimeDefault`.
- `readOnlyRootFilesystem: true`.
- `allowPrivilegeEscalation: false`.
- `automountServiceAccountToken: false` on the pod's ServiceAccount.

The chart never sets `EXAV_ALLOW_SHUTDOWN`. Any client that can reach the
port could otherwise stop the daemon. The chart never sets
`EXAV_ALLOW_HTTP_SCAN` either: that setting can expose the daemon to
server-side request forgery through the `SCANURL` command. The chart render
fails when `extraEnv` sets either name, but it does not check `extraEnvFrom`.

Neither the clamd port nor the ICAP port has authentication or TLS. Only
network reachability protects the daemon. Restrict which pods and
namespaces can reach the Service with a NetworkPolicy (see below) or another
network control.

A `service.type` of `NodePort` or `LoadBalancer` exposes an unauthenticated
port outside the cluster. The chart prints a warning in the install notes in
that case.

## ICAP

Set `icap.enabled: true` to add an `icap://0.0.0.0:1344` listener next to
the clamd listener, and to add port 1344 to the Service. One pod then
serves both protocols over one loaded signature database.

Set `icap.serviceName` to answer on one ICAP service name only. Leave it
empty to answer on all three c-icap-compatible names: `avscan`,
`srv_clamav`, and `virus_scan`.

## NetworkPolicy

`networkPolicy.enabled` is `false` by default. Set `networkPolicy.ingress`
and `networkPolicy.egress` yourself. The chart supplies no default rule
set. An empty `ingress: []` with `Ingress` in `policyTypes` blocks every
client. An empty `egress: []` blocks the signature fetch. Set both lists in
one values file.

Example that allows a named namespace to reach clamd on port 3310, and
allows DNS and HTTPS egress for the signature fetch:

```yaml
networkPolicy:
  enabled: true
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: scanning-clients
      ports:
        - protocol: TCP
          port: 3310
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
      ports:
        - protocol: TCP
          port: 443
```

Add port 1344 to the ingress rule when `icap.enabled` is true, and adjust
the `except` list to the private ranges of your cluster.

## Upgrades and versioning

The chart version, the app version, and the image tag always match the exav
git tag, without the leading `v`. An empty `image.tag` resolves to
`.Chart.AppVersion`.

To upgrade, install a new chart version with the same values file:

```sh
helm upgrade exav oci://ghcr.io/sylvinus/exav-chart --version <X.Y.Z> \
  -f my-values.yaml
```

A `helm upgrade` that passes `-f` or `--set` replaces every value from the
previous release, unless you add `--reuse-values`. Pass the full values file
each time.

## Values

| Key | Type | Default | Description |
|---|---|---|---|
| `replicaCount` | int | `1` | Number of pod replicas. |
| `image.repository` | string | `ghcr.io/sylvinus/exav` | Container image repository. |
| `image.tag` | string | `""` | Image tag. Empty string uses `.Chart.AppVersion`. |
| `image.pullPolicy` | string | `IfNotPresent` | Image pull policy. One of `Always`, `IfNotPresent`, `Never`. |
| `imagePullSecrets` | list | `[]` | Names of secrets for a private registry pull. |
| `nameOverride` | string | `""` | Override for the chart name part of generated resource names. |
| `fullnameOverride` | string | `""` | Override for the full generated resource name. |
| `signatures.sources` | list | `[]` | List of raw CVD mirror URLs or exact feed URLs. |
| `signatures.dbUrl` | string | `""` | URL of a prebuilt signature database. |
| `signatures.existingSecret` | string | `""` | Name of an existing Secret with keys `sig-sources` and `db-url`. |
| `signatures.allowNoDb` | bool | `false` | Allow the pod to start with no signature source. Test use only. The render fails when a source is also set. |
| `signatures.updateIntervalSecs` | string | `""` | Seconds between update checks, floored at 60 by exav. Empty string uses the exav default: 86400 for `sources`, 300 for `dbUrl`. |
| `signatures.startupWaitSecs` | string | `""` | Seconds exav waits for a sidecar to fill an empty `/var/lib/exav`. Applies only with no `sources` and no `dbUrl`. Empty string uses 1800, or 0 when `allowNoDb` is true. |
| `signatures.persistence.enabled` | bool | `false` | Store signatures on a PersistentVolumeClaim instead of an `emptyDir`. |
| `signatures.persistence.existingClaim` | string | `""` | Name of an existing PVC. Skips creation of a chart-managed PVC. Needs `enabled: true`. |
| `signatures.persistence.storageClassName` | string | `""` | StorageClass for the chart-managed PVC. Empty string uses the cluster default class. `-` sets an empty class, to bind a pre-provisioned PV. |
| `signatures.persistence.accessModes` | list | `[ReadWriteOnce]` | Access modes for the chart-managed PVC. |
| `signatures.persistence.size` | string | `2Gi` | Requested size for the chart-managed PVC. |
| `signatures.persistence.annotations` | object | `{}` | Extra annotations for the chart-managed PVC. Values are rendered as strings. |
| `archivePasswords.existingSecret` | string | `""` | Name of an existing Secret that holds an archive password list file. |
| `archivePasswords.key` | string | `passwords` | Key inside the existing Secret that holds the password list file. |
| `spill.sizeLimit` | string | `8Gi` | Maximum total spill size on disk. Only binary suffixes: the chart derives the exav limit by dropping the `i`. |
| `spill.medium` | string | `""` | Storage medium for the spill `emptyDir`. Empty string uses node disk. |
| `spill.thresholdBytes` | string | `""` | Spill threshold size. Empty string uses the exav default. |
| `spill.maxBytes` | string | `""` | Maximum spill size per scan. Empty string uses the exav default. `0` or `off` removes the per-scan cap. |
| `workers` | string | `""` | Positive worker count, or `threads` for a thread pool. Empty string uses the exav default. |
| `icap.enabled` | bool | `false` | Serve the ICAP protocol on port 1344, in addition to clamd. |
| `icap.serviceName` | string | `""` | ICAP service name: one path segment of letters, digits, `_`, `.`, and `-`. Empty string answers on all three default names. |
| `service.type` | string | `ClusterIP` | Kubernetes Service type. |
| `service.clamdPort` | int | `3310` | Service port for the clamd protocol. |
| `service.icapPort` | int | `1344` | Service port for the ICAP protocol. |
| `service.annotations` | object | `{}` | Extra annotations for the Service. Values are rendered as strings. |
| `resources` | object | `{}` | Container resource requests and limits. |
| `serviceAccount.create` | bool | `true` | Create a ServiceAccount for the pod. |
| `serviceAccount.name` | string | `""` | Name of the ServiceAccount to use. Empty string uses the generated fullname. |
| `serviceAccount.annotations` | object | `{}` | Extra annotations for the ServiceAccount. Values are rendered as strings. |
| `podSecurityContext.runAsNonRoot` | bool | `true` | Require the pod to run as a non-root user. |
| `podSecurityContext.runAsUser` | int | `65532` | User ID to run the container process as. |
| `podSecurityContext.runAsGroup` | int | `65532` | Group ID to run the container process as. |
| `podSecurityContext.fsGroup` | int | `65532` | Group ID that owns mounted volumes. |
| `podSecurityContext.seccompProfile.type` | string | `RuntimeDefault` | Seccomp profile type. |
| `securityContext.allowPrivilegeEscalation` | bool | `false` | Forbid privilege escalation from the container process. |
| `securityContext.readOnlyRootFilesystem` | bool | `true` | Mount the root filesystem read-only. |
| `securityContext.capabilities.drop` | list | `[ALL]` | Linux capabilities to drop. |
| `probes.startup.periodSeconds` | int | `10` | Seconds between startup probe checks. |
| `probes.startup.timeoutSeconds` | int | `5` | Seconds before a startup probe check times out. |
| `probes.startup.failureThreshold` | string | `""` | Positive integer, or empty string to compute a default from the effective `startupWaitSecs`. It also sets `progressDeadlineSeconds`. |
| `probes.liveness.periodSeconds` | int | `30` | Seconds between liveness probe checks. |
| `probes.liveness.timeoutSeconds` | int | `5` | Seconds before a liveness probe check times out. |
| `probes.liveness.failureThreshold` | int | `3` | Consecutive liveness probe failures before the pod is restarted. |
| `probes.readiness.periodSeconds` | int | `10` | Seconds between readiness probe checks. |
| `probes.readiness.timeoutSeconds` | int | `5` | Seconds before a readiness probe check times out. |
| `probes.readiness.failureThreshold` | int | `3` | Consecutive readiness probe failures before the pod is marked not ready. |
| `terminationGracePeriodSeconds` | int | `30` | Seconds the pod gets to shut down after SIGTERM. |
| `updateStrategy` | object | `{}` | Deployment update strategy. Empty object computes a default from persistence and accessModes. |
| `podDisruptionBudget.enabled` | bool | `false` | Create a PodDisruptionBudget. |
| `podDisruptionBudget.minAvailable` | int | `1` | Minimum available pods. Set at most one of `minAvailable` and `maxUnavailable`. A `null` value counts as unset. With `replicaCount: 1`, a value of 1 blocks node drains. |
| `podDisruptionBudget.maxUnavailable` | string | `""` | Maximum unavailable pods. Set at most one of `minAvailable` and `maxUnavailable`. A `null` value counts as unset. |
| `networkPolicy.enabled` | bool | `false` | Create a NetworkPolicy. |
| `networkPolicy.policyTypes` | list | `[Ingress, Egress]` | Policy types the NetworkPolicy applies to. |
| `networkPolicy.ingress` | list | `[]` | Ingress rules, rendered verbatim. |
| `networkPolicy.egress` | list | `[]` | Egress rules, rendered verbatim. |
| `podAnnotations` | object | `{}` | Extra annotations for the pod template. Values are rendered as strings. |
| `podLabels` | object | `{}` | Extra labels for the pod template. Values are rendered as strings. |
| `extraEnv` | list | `[]` | Extra environment variables for the container. The render fails for `EXAV_ALLOW_SHUTDOWN` and `EXAV_ALLOW_HTTP_SCAN`. A duplicate name overrides the chart value. |
| `extraEnvFrom` | list | `[]` | Extra `envFrom` entries for the container. |
| `extraVolumes` | list | `[]` | Extra volumes for the pod. |
| `extraVolumeMounts` | list | `[]` | Extra volume mounts for the container. |
| `nodeSelector` | object | `{}` | Node selector for pod placement. |
| `tolerations` | list | `[]` | Tolerations for pod placement. |
| `affinity` | object | `{}` | Affinity rules for pod placement. |
| `topologySpreadConstraints` | list | `[]` | Topology spread constraints for pod placement. |
| `priorityClassName` | string | `""` | Priority class name for the pod. |
