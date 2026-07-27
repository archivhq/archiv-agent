{{/* Chart name, overridable. */}}
{{- define "archiv-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully-qualified app name. */}}
{{- define "archiv-agent.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "archiv-agent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "archiv-agent.labels" -}}
helm.sh/chart: {{ include "archiv-agent.chart" . }}
{{ include "archiv-agent.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/component: data-plane
app.kubernetes.io/part-of: archiv
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "archiv-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "archiv-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* ServiceAccount name. */}}
{{- define "archiv-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "archiv-agent.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Fully-resolved image reference. Digest wins over tag (trust/03 §3.4 — pin by digest in prod);
tag defaults to the chart appVersion. "latest" is refused outright (trust/03 §4).
*/}}
{{- define "archiv-agent.image" -}}
{{- $registry := .Values.image.registry | default "ghcr.io" -}}
{{- $repo := .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{- printf "%s/%s@%s" $registry $repo .Values.image.digest -}}
{{- else -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if eq (lower (toString $tag)) "latest" -}}
{{- fail "image.tag must not be 'latest' (trust/03 §4 — pin a version or, better, image.digest)" -}}
{{- end -}}
{{- printf "%s/%s:%s" $registry $repo $tag -}}
{{- end -}}
{{- end -}}
