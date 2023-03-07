#build stage
FROM golang:alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY . /app
RUN go build -o /app/main -v

#final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/main /app/main
COPY --from=builder /app/public /app/public
WORKDIR /app
ENTRYPOINT /app/main
LABEL Name=mongogo Version=0.0.1
EXPOSE 9000
