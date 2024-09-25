FROM golang:alpine AS build
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o oidc-ipd .

FROM alpine:edge
WORKDIR /app

COPY --from=build /app/oidc-ipd .
RUN apk --no-cache add ca-certificates tzdata
ENTRYPOINT ["/app/oidc-ipd"]