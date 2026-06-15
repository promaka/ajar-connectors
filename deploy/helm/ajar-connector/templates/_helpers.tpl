{{/* SPDX-License-Identifier: Apache-2.0 */}}
{{- define "ajar-connector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ajar-connector.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "ajar-connector.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "ajar-connector.labels" -}}
app.kubernetes.io/name: {{ include "ajar-connector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "ajar-connector.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ajar-connector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ajar-connector.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "ajar-connector.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* The name of the Secret holding the signing seed (existing or chart-created). */}}
{{- define "ajar-connector.seedSecretName" -}}
{{- if .Values.signingSeed.existingSecret -}}
{{- .Values.signingSeed.existingSecret -}}
{{- else -}}
{{- printf "%s-seed" (include "ajar-connector.fullname" .) -}}
{{- end -}}
{{- end -}}
