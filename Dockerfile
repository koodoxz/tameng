# SVALINN-GO Dockerfile
# Multi-stage build for minimal image size

# Build stage
FROM golang:1.26.5-alpine AS builder

# Install build dependencies (CGO needed for SQLite)
RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build with CGO enabled for SQLite
ENV CGO_ENABLED=1
RUN go build -ldflags="-s -w" -o svalinn ./cmd/svalinn

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy binary
COPY --from=builder /app/svalinn .

# Copy config
COPY configs/ ./configs/

# Create data directory
RUN mkdir -p /app/data

# Expose ports
EXPOSE 10000
EXPOSE 10443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:10000/health || exit 1

# Run as non-root
RUN adduser -D -u 1000 svalinn
USER svalinn

# Start
ENTRYPOINT ["./svalinn"]
CMD ["-config", "configs/svalinn.yaml"]
