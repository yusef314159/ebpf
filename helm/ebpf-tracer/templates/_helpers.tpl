{{/*
Expand the name of the chart.
*/}}
{{- define "ebpf-tracer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "ebpf-tracer.fullname" -}}
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
{{- define "ebpf-tracer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ebpf-tracer.labels" -}}
helm.sh/chart: {{ include "ebpf-tracer.chart" . }}
{{ include "ebpf-tracer.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: monitoring
app.kubernetes.io/part-of: observability
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ebpf-tracer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ebpf-tracer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "ebpf-tracer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ebpf-tracer.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the cluster role to use
*/}}
{{- define "ebpf-tracer.clusterRoleName" -}}
{{- if .Values.rbac.create }}
{{- default (include "ebpf-tracer.fullname" .) .Values.rbac.name }}
{{- else }}
{{- default "default" .Values.rbac.name }}
{{- end }}
{{- end }}

{{/*
Create the image name
*/}}
{{- define "ebpf-tracer.image" -}}
{{- $registry := .Values.global.imageRegistry | default .Values.image.registry -}}
{{- $repository := .Values.image.repository -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if $registry }}
{{- printf "%s/%s:%s" $registry $repository $tag }}
{{- else }}
{{- printf "%s:%s" $repository $tag }}
{{- end }}
{{- end }}

{{/*
Create the config checksum annotation
*/}}
{{- define "ebpf-tracer.configChecksum" -}}
checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
{{- end }}

{{/*
Create security context
*/}}
{{- define "ebpf-tracer.securityContext" -}}
{{- with .Values.securityContext }}
{{- toYaml . }}
{{- end }}
{{- end }}

{{/*
Create pod security context
*/}}
{{- define "ebpf-tracer.podSecurityContext" -}}
{{- with .Values.podSecurityContext }}
{{- toYaml . }}
{{- end }}
{{- end }}

{{/*
Create resource limits
*/}}
{{- define "ebpf-tracer.resources" -}}
{{- with .Values.resources }}
{{- toYaml . }}
{{- end }}
{{- end }}

{{/*
Create node selector
*/}}
{{- define "ebpf-tracer.nodeSelector" -}}
{{- with .Values.nodeSelector }}
{{- toYaml . }}
{{- end }}
{{- end }}

{{/*
Create tolerations
*/}}
{{- define "ebpf-tracer.tolerations" -}}
{{- with .Values.tolerations }}
{{- toYaml . }}
{{- end }}
{{- end }}

{{/*
Create affinity
*/}}
{{- define "ebpf-tracer.affinity" -}}
{{- with .Values.affinity }}
{{- toYaml . }}
{{- end }}
{{- end }}

{{/*
Create environment variables
*/}}
{{- define "ebpf-tracer.env" -}}
- name: NODE_NAME
  valueFrom:
    fieldRef:
      fieldPath: spec.nodeName
- name: POD_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: POD_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
- name: POD_IP
  valueFrom:
    fieldRef:
      fieldPath: status.podIP
{{- with .Values.env }}
{{- toYaml . }}
{{- end }}
{{- end }}

{{/*
Create volume mounts
*/}}
{{- define "ebpf-tracer.volumeMounts" -}}
- name: config
  mountPath: /etc/ebpf-tracer
  readOnly: true
- name: scripts
  mountPath: /scripts
  readOnly: true
{{- if .Values.volumeMounts.hostSys }}
- name: host-sys
  mountPath: /sys
  readOnly: true
{{- end }}
{{- if .Values.volumeMounts.hostProc }}
- name: host-proc
  mountPath: /host/proc
  readOnly: true
{{- end }}
{{- if .Values.volumeMounts.hostDev }}
- name: host-dev
  mountPath: /host/dev
  readOnly: true
{{- end }}
{{- if .Values.volumeMounts.bpfMaps }}
- name: bpf-maps
  mountPath: /sys/fs/bpf
{{- end }}
{{- if .Values.volumeMounts.debugfs }}
- name: debugfs
  mountPath: /sys/kernel/debug
{{- end }}
{{- with .Values.extraVolumeMounts }}
{{- toYaml . }}
{{- end }}
{{- end }}

{{/*
Create volumes
*/}}
{{- define "ebpf-tracer.volumes" -}}
- name: config
  configMap:
    name: {{ include "ebpf-tracer.fullname" . }}-config
    defaultMode: 0644
- name: scripts
  configMap:
    name: {{ include "ebpf-tracer.fullname" . }}-scripts
    defaultMode: 0755
{{- if .Values.volumeMounts.hostSys }}
- name: host-sys
  hostPath:
    path: /sys
    type: Directory
{{- end }}
{{- if .Values.volumeMounts.hostProc }}
- name: host-proc
  hostPath:
    path: /proc
    type: Directory
{{- end }}
{{- if .Values.volumeMounts.hostDev }}
- name: host-dev
  hostPath:
    path: /dev
    type: Directory
{{- end }}
{{- if .Values.volumeMounts.bpfMaps }}
- name: bpf-maps
  hostPath:
    path: /sys/fs/bpf
    type: DirectoryOrCreate
{{- end }}
{{- if .Values.volumeMounts.debugfs }}
- name: debugfs
  hostPath:
    path: /sys/kernel/debug
    type: Directory
{{- end }}
{{- with .Values.extraVolumes }}
{{- toYaml . }}
{{- end }}
{{- end }}
