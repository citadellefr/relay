FROM golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# VERSION is written next to the sources by whoever deploys them; without it
# the binary says "dev"
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=$(cat VERSION 2>/dev/null || echo dev)" -o /out/gateway .

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/gateway /usr/local/bin/gateway
ENTRYPOINT ["gateway"]
