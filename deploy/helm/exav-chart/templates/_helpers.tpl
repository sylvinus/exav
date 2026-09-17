{{/*
The chart name defaults to "exav", not .Chart.Name, so the release name
combines with "exav" and not with "exav-chart".
*/}}
{{- define "exav-chart.name" -}}
{{- default "exav" .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "exav-chart.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "exav-chart.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "exav-chart.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "exav-chart.labels" -}}
helm.sh/chart: {{ include "exav-chart.chart" . }}
{{ include "exav-chart.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "exav-chart.selectorLabels" -}}
app.kubernetes.io/name: {{ include "exav-chart.name" . | quote }}
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}

{{- define "exav-chart.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "exav-chart.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "exav-chart.secretName" -}}
{{- default (include "exav-chart.fullname" .) .Values.signatures.existingSecret -}}
{{- end -}}

{{- define "exav-chart.listen" -}}
{{- $listen := "clamd://0.0.0.0:3310" -}}
{{- if .Values.icap.enabled -}}
{{- $listen = printf "%s,icap://0.0.0.0:1344" $listen -}}
{{- if .Values.icap.serviceName -}}
{{- $listen = printf "%s/%s" $listen .Values.icap.serviceName -}}
{{- end -}}
{{- end -}}
{{- $listen -}}
{{- end -}}

{{/*
true when the value is neither unset nor an empty string. An integer 0 is
set; a plain `if` or `default` would treat it as unset.
*/}}
{{- define "exav-chart.isSet" -}}
{{- if and (not (kindIs "invalid" .)) (ne (toString .) "") -}}true{{- end -}}
{{- end -}}

{{/*
Effective EXAV_STARTUP_WAIT_SECS, as a string: the set value, else 0 when
allowNoDb has no signature source to wait for, else the exav default.
*/}}
{{- define "exav-chart.startupWaitSecs" -}}
{{- if include "exav-chart.isSet" .Values.signatures.startupWaitSecs -}}
{{- .Values.signatures.startupWaitSecs | toString -}}
{{- else if .Values.signatures.allowNoDb -}}
0
{{- else -}}
1800
{{- end -}}
{{- end -}}

{{/*
Effective startup probe failureThreshold: the set value, else a threshold
sized from the effective startup wait.
*/}}
{{- define "exav-chart.startupFailureThreshold" -}}
{{- if include "exav-chart.isSet" .Values.probes.startup.failureThreshold -}}
{{- .Values.probes.startup.failureThreshold -}}
{{- else -}}
{{- $wait := int (include "exav-chart.startupWaitSecs" .) -}}
{{- $period := int .Values.probes.startup.periodSeconds -}}
{{/* 600 s of headroom above the signature wait covers the fetch and the first load. */}}
{{- div (add (add $wait 600) (sub $period 1)) $period -}}
{{- end -}}
{{- end -}}

{{/*
Convert a size string (16M, 2G, 8Gi, 1024, off, 0) to an integer number of
bytes, base 1024. exav does not accept the "i" suffix, so the chart strips it.
*/}}
{{- define "exav-chart.sizeBytes" -}}
{{- $s := toString . | lower -}}
{{- if or (eq $s "off") (eq $s "0") (eq $s "") -}}
0
{{- else -}}
{{- if hasSuffix "i" $s -}}{{- $s = trimSuffix "i" $s -}}{{- end -}}
{{- $unit := 1 -}}
{{- if hasSuffix "k" $s -}}{{- $unit = 1024 -}}{{- $s = trimSuffix "k" $s -}}
{{- else if hasSuffix "m" $s -}}{{- $unit = 1048576 -}}{{- $s = trimSuffix "m" $s -}}
{{- else if hasSuffix "g" $s -}}{{- $unit = 1073741824 -}}{{- $s = trimSuffix "g" $s -}}
{{- else if hasSuffix "t" $s -}}{{- $unit = 1099511627776 -}}{{- $s = trimSuffix "t" $s -}}
{{- end -}}
{{- mul (int64 $s) $unit -}}
{{- end -}}
{{- end -}}

{{/*
Fail the render early with a clear message, instead of a hard-to-read
Kubernetes API rejection after apply.
*/}}
{{- define "exav-chart.validate" -}}
{{- if not (or .Values.signatures.sources .Values.signatures.dbUrl .Values.signatures.existingSecret .Values.signatures.allowNoDb) -}}
{{- fail "exav-chart: set signatures.sources, signatures.dbUrl, or signatures.existingSecret. Set signatures.allowNoDb=true only for a test with no signatures." -}}
{{- end -}}
{{- if and .Values.signatures.existingSecret (or .Values.signatures.sources .Values.signatures.dbUrl) -}}
{{- fail "exav-chart: signatures.existingSecret replaces the chart Secret. Put sig-sources and db-url inside that Secret instead of setting signatures.sources or signatures.dbUrl." -}}
{{- end -}}
{{- if and .Values.signatures.persistence.enabled (gt (int .Values.replicaCount) 1) (not (has "ReadWriteMany" .Values.signatures.persistence.accessModes)) -}}
{{- fail "exav-chart: replicaCount > 1 with signatures.persistence.enabled needs signatures.persistence.accessModes to include ReadWriteMany, or replicaCount set to 1, or signatures.persistence.enabled set to false." -}}
{{- end -}}
{{- if and .Values.podDisruptionBudget.enabled (include "exav-chart.isSet" .Values.podDisruptionBudget.minAvailable) (include "exav-chart.isSet" .Values.podDisruptionBudget.maxUnavailable) -}}
{{- fail "exav-chart: set only one of podDisruptionBudget.minAvailable and podDisruptionBudget.maxUnavailable." -}}
{{- end -}}
{{- if and .Values.signatures.persistence.existingClaim (not .Values.signatures.persistence.enabled) -}}
{{- fail "exav-chart: signatures.persistence.existingClaim needs signatures.persistence.enabled set to true." -}}
{{- end -}}
{{- if and .Values.signatures.allowNoDb (or .Values.signatures.sources .Values.signatures.dbUrl .Values.signatures.existingSecret) -}}
{{- fail "exav-chart: signatures.allowNoDb=true cannot combine with signatures.sources, signatures.dbUrl, or signatures.existingSecret." -}}
{{- end -}}
{{- range .Values.signatures.sources -}}
{{- if contains "," . -}}
{{- fail "exav-chart: signatures.sources entries must not contain a comma; the chart joins the list with commas." -}}
{{- end -}}
{{- end -}}
{{- range .Values.extraEnv -}}
{{- if or (eq .name "EXAV_ALLOW_SHUTDOWN") (eq .name "EXAV_ALLOW_HTTP_SCAN") -}}
{{- fail "exav-chart: extraEnv must not set EXAV_ALLOW_SHUTDOWN or EXAV_ALLOW_HTTP_SCAN." -}}
{{- end -}}
{{- end -}}
{{- $spillTotal := int64 (include "exav-chart.sizeBytes" .Values.spill.sizeLimit) -}}
{{- $spillMaxObject := int64 2147483648 -}}
{{- if include "exav-chart.isSet" .Values.spill.maxBytes -}}
{{- $spillMaxObject = int64 (include "exav-chart.sizeBytes" .Values.spill.maxBytes) -}}
{{- end -}}
{{- $spillThreshold := int64 16777216 -}}
{{- if include "exav-chart.isSet" .Values.spill.thresholdBytes -}}
{{- $spillThreshold = int64 (include "exav-chart.sizeBytes" .Values.spill.thresholdBytes) -}}
{{- end -}}
{{- if and (ne $spillMaxObject 0) (gt $spillMaxObject $spillTotal) -}}
{{- fail "exav-chart: spill.maxBytes must not exceed spill.sizeLimit; raise spill.sizeLimit or lower spill.maxBytes." -}}
{{- end -}}
{{- if and (ne $spillMaxObject 0) (gt $spillThreshold $spillMaxObject) -}}
{{- fail "exav-chart: spill.thresholdBytes must not exceed spill.maxBytes; raise spill.maxBytes or lower spill.thresholdBytes." -}}
{{- end -}}
{{- end -}}
