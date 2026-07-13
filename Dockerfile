# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.26.5

FROM golang:${GO_VERSION}-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations

RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -buildid=" \
      -o /out/collector ./cmd/collector \
    && CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -buildid=" \
      -o /out/controlplane ./cmd/controlplane

FROM golang:${GO_VERSION}-bookworm AS quality

ARG GOLANGCI_LINT_VERSION=v2.12.2
ARG GOSEC_VERSION=v2.25.0
ARG GOVULNCHECK_VERSION=v1.1.4

ENV GOBIN=/usr/local/bin
WORKDIR /src

# Each tool is version-pinned. No remote installer script is executed.
RUN go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION} \
    && go install github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION} \
    && go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}

COPY go.mod go.sum ./
RUN go mod download

COPY .golangci.yml ./
COPY scripts ./scripts
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations

RUN chmod 0555 /src/scripts/run-quality-checks.sh

CMD ["/src/scripts/run-quality-checks.sh"]

FROM scratch AS controlplane

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/controlplane /controlplane

USER 65532:65532
ENTRYPOINT ["/controlplane"]

FROM scratch AS collector

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/collector /collector

USER 65532:65532
ENTRYPOINT ["/collector"]
