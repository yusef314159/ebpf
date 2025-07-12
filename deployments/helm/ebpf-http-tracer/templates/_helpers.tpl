{{/*
Expand the name of the chart.
*/}}
{{- define "ebpf-http-tracer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "ebpf-http-tracer.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "ebpf-http-tracer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ebpf-http-tracer.labels" -}}
helm.sh/chart: {{ include "ebpf-http-tracer.chart" . }}
{{ include "ebpf-http-tracer.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ebpf-http-tracer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ebpf-http-tracer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "ebpf-http-tracer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ebpf-http-tracer.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the cluster role to use
*/}}
{{- define "ebpf-http-tracer.clusterRoleName" -}}
{{- if .Values.rbac.create }}
{{- default (include "ebpf-http-tracer.fullname" .) .Values.rbac.clusterRoleName }}
{{- else }}
{{- default "default" .Values.rbac.clusterRoleName }}
{{- end }}
{{- end }}

{{/*
Create the name of the cluster role binding to use
*/}}
{{- define "ebpf-http-tracer.clusterRoleBindingName" -}}
{{- if .Values.rbac.create }}
{{- default (include "ebpf-http-tracer.fullname" .) .Values.rbac.clusterRoleBindingName }}
{{- else }}
{{- default "default" .Values.rbac.clusterRoleBindingName }}
{{- end }}
{{- end }}

{{/*
Create image pull secrets
*/}}
{{- define "ebpf-http-tracer.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
{{- range .Values.global.imagePullSecrets }}
- name: {{ . }}
{{- end }}
{{- else if .Values.imagePullSecrets }}
{{- range .Values.imagePullSecrets }}
- name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create the image repository
*/}}
{{- define "ebpf-http-tracer.image" -}}
{{- if .Values.global.imageRegistry }}
{{- printf "%s/%s" .Values.global.imageRegistry .Values.image.repository }}
{{- else }}
{{- .Values.image.repository }}
{{- end }}
{{- end }}

{{/*
Create the image tag
*/}}
{{- define "ebpf-http-tracer.imageTag" -}}
{{- .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
Create the full image name
*/}}
{{- define "ebpf-http-tracer.imageFullName" -}}
{{- printf "%s:%s" (include "ebpf-http-tracer.image" .) (include "ebpf-http-tracer.imageTag" .) }}
{{- end }}

{{/*
Create Jaeger collector URL
*/}}
{{- define "ebpf-http-tracer.jaegerCollectorUrl" -}}
{{- if .Values.jaeger.enabled }}
{{- printf "http://%s-jaeger-collector.%s.svc.cluster.local:14268/api/traces" .Release.Name .Release.Namespace }}
{{- else }}
{{- .Values.config.tracing.jaegerCollectorUrl }}
{{- end }}
{{- end }}

{{/*
Create OTLP endpoint
*/}}
{{- define "ebpf-http-tracer.otlpEndpoint" -}}
{{- if .Values.jaeger.enabled }}
{{- printf "%s-jaeger-collector.%s.svc.cluster.local:14250" .Release.Name .Release.Namespace }}
{{- else }}
{{- .Values.config.tracing.otlpEndpoint }}
{{- end }}
{{- end }}

{{/*
Create Prometheus service monitor labels
*/}}
{{- define "ebpf-http-tracer.serviceMonitorLabels" -}}
{{- if .Values.monitoring.prometheus.serviceMonitor.labels }}
{{- toYaml .Values.monitoring.prometheus.serviceMonitor.labels }}
{{- end }}
{{- end }}

{{/*
Create Prometheus service monitor annotations
*/}}
{{- define "ebpf-http-tracer.serviceMonitorAnnotations" -}}
{{- if .Values.monitoring.prometheus.serviceMonitor.annotations }}
{{- toYaml .Values.monitoring.prometheus.serviceMonitor.annotations }}
{{- end }}
{{- end }}

{{/*
Create Grafana dashboard labels
*/}}
{{- define "ebpf-http-tracer.grafanaDashboardLabels" -}}
{{- if .Values.monitoring.grafana.dashboards.enabled }}
{{ .Values.monitoring.grafana.dashboards.label }}: {{ .Values.monitoring.grafana.dashboards.labelValue | quote }}
{{- end }}
{{- end }}

{{/*
Validate configuration
*/}}
{{- define "ebpf-http-tracer.validateConfig" -}}
{{- if and .Values.config.tracing.enabled (not .Values.jaeger.enabled) (not .Values.config.tracing.jaegerCollectorUrl) }}
{{- fail "Jaeger collector URL must be specified when distributed tracing is enabled but Jaeger is not deployed" }}
{{- end }}
{{- if and .Values.config.analytics.enabled (lt .Values.config.analytics.bufferSize 1000) }}
{{- fail "Analytics buffer size must be at least 1000" }}
{{- end }}
{{- if and .Values.config.analytics.enabled (lt .Values.config.analytics.workerThreads 1) }}
{{- fail "Analytics worker threads must be at least 1" }}
{{- end }}
{{- end }}
