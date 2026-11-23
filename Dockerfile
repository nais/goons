FROM golang:1.27-alpine AS builder
WORKDIR /src
COPY go.* /src/
RUN go mod download
COPY . /src
RUN go build -o bin/goons ./cmd/goons

FROM gcr.io/distroless/base
WORKDIR /app
COPY --from=builder /src/bin/goons /app/goons
ENTRYPOINT ["/app/goons"]
