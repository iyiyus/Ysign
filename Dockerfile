# ---- build stage ----
FROM golang:1.27-alpine AS build

WORKDIR /src

# Cache module downloads independently of source changes
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Version is injected at build time (CI passes the git tag, e.g. 1.1.0)
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/ysign ./cmd/ysign

# ---- runtime stage ----
FROM alpine:3.21

# ca-certificates is required for the best-effort OCSP checks (-C)
RUN apk add --no-cache ca-certificates && \
    adduser -D -u 1000 ysign

COPY --from=build /out/ysign /usr/local/bin/ysign

USER ysign
WORKDIR /work

ENTRYPOINT ["ysign"]
