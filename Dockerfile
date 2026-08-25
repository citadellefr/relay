FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/gateway .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/gateway /usr/local/bin/gateway
ENTRYPOINT ["gateway"]
