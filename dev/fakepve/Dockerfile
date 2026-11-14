# Dev target for the Virtual machines section: a fake Proxmox VE cluster
# (cmd/fakepve). Build context = the backend root.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/fakepve ./cmd/fakepve
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /fakepve ./cmd/fakepve

FROM alpine:3.22
COPY --from=build /fakepve /usr/local/bin/fakepve
VOLUME /data
EXPOSE 8006
ENTRYPOINT ["/usr/local/bin/fakepve"]
