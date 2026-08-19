{{/* SPDX-License-Identifier: Apache-2.0 */}}
{{- define "connector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "connector.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "connector.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "connector.labels" -}}
app.kubernetes.io/name: {{ include "connector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "connector.selectorLabels" -}}
app.kubernetes.io/name: {{ include "connector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "connector.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "connector.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* The name of the Secret holding the signing seed (existing or chart-created). */}}
{{- define "connector.seedSecretName" -}}
{{- if .Values.signingSeed.existingSecret -}}
{{- .Values.signingSeed.existingSecret -}}
{{- else -}}
{{- printf "%s-seed" (include "connector.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Image ref: pin by digest when set, else by an explicit tag. A floating
     "latest" (or no tag) is rejected — production must pin a real version. */}}
{{- define "connector.repository" -}}
{{- if .Values.image.repository -}}
{{- .Values.image.repository -}}
{{- else if .Values.connector.name -}}
{{- printf "%s/ajar-connector-%s" .Values.image.registry .Values.connector.name -}}
{{- else -}}
{{- fail "set connector.name to a published connector (asterix, tak-cot, adsb, mavlink, generic, tak-egress), or image.repository to an image you built" -}}
{{- end -}}
{{- end -}}

{{- define "connector.image" -}}
{{- $repo := include "connector.repository" . -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $repo .Values.image.digest -}}
{{- else if or (not .Values.image.tag) (eq .Values.image.tag "latest") -}}
{{- fail "image.digest or an explicit image.tag is required (a pinned version, not \"latest\") — set image.digest=sha256:… (recommended) or image.tag=1.0.0" -}}
{{- else -}}
{{- printf "%s:%s" $repo .Values.image.tag -}}
{{- end -}}
{{- end -}}

{{/* The connector's config file. Every connector on the shared runtime takes a
     TOML path as its first argument, so a release with neither inline config nor
     an existing ConfigMap would deploy a pod that cannot start. Rejected here
     rather than at 3am in a crash-loop. */}}
{{- define "connector.configVolumeName" -}}
{{- if .Values.connector.existingConfigMap -}}
{{- .Values.connector.existingConfigMap -}}
{{- else if .Values.connector.config -}}
{{- printf "%s-config" (include "connector.fullname" .) -}}
{{- else -}}
{{- fail "connector.config is required — the connector's TOML, passed as its first argument (see each connector's <name>.example.toml). Or set connector.existingConfigMap to one you manage." -}}
{{- end -}}
{{- end -}}
