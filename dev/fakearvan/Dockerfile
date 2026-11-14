# Dev target for the Cloud section: a fake ArvanCloud API (cmd/fakearvan).
# Build context = the backend root.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/fakearvan ./cmd/fakearvan
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /fakearvan ./cmd/fakearvan

FROM alpine:3.22
COPY --from=build /fakearvan /usr/local/bin/fakearvan
EXPOSE 8091
ENTRYPOINT ["/usr/local/bin/fakearvan"]
