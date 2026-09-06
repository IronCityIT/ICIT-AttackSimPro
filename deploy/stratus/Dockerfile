# Cloud Attack Simulation runner — DESCRIBED, NOT BUILT by CI/agents.
# Internal tool: Stratus Red Team. Bill builds/runs this on an authorized runner against
# a disposable cloud sandbox only. No detonation happens in this repo or in CI.
FROM golang:1.22-alpine AS build
# Pin to a specific release before building (Bill).
RUN go install github.com/datadog/stratus-red-team/v2/cmd/stratus@latest

FROM alpine:3.20
RUN adduser -D -H sim
COPY --from=build /go/bin/stratus /usr/local/bin/stratus
USER sim
ENTRYPOINT ["stratus"]
CMD ["--help"]
