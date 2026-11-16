# syntax=docker/dockerfile:1

FROM alpine:3.22
RUN apk add --no-cache ca-certificates curl tini
COPY --chmod=0755 entrypoint.sh /usr/local/bin/zedr-agent-entrypoint
ENV TINI_SUBREAPER=true
VOLUME ["/var/lib/zedr"]
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/zedr-agent-entrypoint"]
