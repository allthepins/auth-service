# Stage 1: build the application
FROM golang:1.24.5-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum to download dependencies
# (Only copy go.mod for now, update to also copy go.sum when it exists)
COPY go.mod ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /auth-service ./cmd/api

# Stage 2: Create the final image
FROM alpine:latest

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /auth-service .

# Expose port app will run on
EXPOSE 8080

# Run the executable
ENTRYPOINT ["./auth-service"]
