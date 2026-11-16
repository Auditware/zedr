{{- define "zedr.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 52 | trimSuffix "-" -}}
{{- end -}}

{{- define "zedr.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 52 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "zedr.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 52 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 52 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "zedr.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "zedr.labels" -}}
helm.sh/chart: {{ include "zedr.chart" . }}
{{ include "zedr.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "zedr.selectorLabels" -}}
app.kubernetes.io/name: {{ include "zedr.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "zedr.containerPort" -}}
7770
{{- end -}}

{{- define "zedr.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (required "image.digest or image.tag is required" .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "zedr.serverUrl" -}}
{{- $url := required "server.url is required: the public https origin agents and operators use, for example https://zedr.example.com" .Values.server.url -}}
{{- if gt (len $url) 64 -}}
{{- fail (printf "server.url is %d bytes long, the limit is 64 because it is patched into agent binaries" (len $url)) -}}
{{- end -}}
{{- if not (regexMatch "^https://[^/?#\\s]+$" $url) -}}
{{- fail "server.url must be an https origin without a path or trailing slash, for example https://zedr.example.com" -}}
{{- end -}}
{{- $url -}}
{{- end -}}

{{- define "zedr.serverHostname" -}}
{{- (urlParse (include "zedr.serverUrl" .)).hostname -}}
{{- end -}}

{{- define "zedr.secretName" -}}
{{- if eq .Values.secrets.mode "create" -}}
{{- printf "%s-secrets" (include "zedr.fullname" .) -}}
{{- else if eq .Values.secrets.mode "existing" -}}
{{- required "secrets.existingSecret is required when secrets.mode=existing" .Values.secrets.existingSecret -}}
{{- else -}}
{{- fail (printf "secrets.mode must be create or existing, got %q" .Values.secrets.mode) -}}
{{- end -}}
{{- end -}}

{{- define "zedr.tlsSecretName" -}}
{{- if eq .Values.tls.mode "certManager" -}}
{{- printf "%s-tls" (include "zedr.fullname" .) -}}
{{- else if eq .Values.tls.mode "existingSecret" -}}
{{- required "tls.existingSecret is required when tls.mode=existingSecret" .Values.tls.existingSecret -}}
{{- else -}}
{{- fail (printf "tls.mode must be existingSecret or certManager, got %q" .Values.tls.mode) -}}
{{- end -}}
{{- end -}}
