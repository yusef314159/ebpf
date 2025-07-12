# Multi-stage build for optimized production image
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    linux-headers \
    libbpf-dev \
    clang \
    llvm \
    make \
    git \
    pkgconfig

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build eBPF programs first
RUN make build-ebpf

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o tracer ./cmd/tracer

# Production stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libbpf \
    libelf \
    zlib

# Create non-root user for security
RUN addgroup -g 1001 -S ebpf && \
    adduser -u 1001 -S ebpf -G ebpf

# Create necessary directories
RUN mkdir -p /app/config /app/logs /app/data && \
    chown -R ebpf:ebpf /app

# Copy binary from builder stage
COPY --from=builder /app/tracer /app/tracer

# Copy eBPF object files
COPY --from=builder /app/src/*.o /app/src/

# Copy default configuration
COPY --chown=ebpf:ebpf config/default.yaml /app/config/default.yaml

# Copy documentation
COPY --chown=ebpf:ebpf docs/ /app/docs/
COPY --chown=ebpf:ebpf README.md /app/

# Set working directory
WORKDIR /app

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -f tracer || exit 1

# Use non-root user
USER ebpf

# Set environment variables
ENV HTTP_TRACER_CONFIG_FILE=/app/config/default.yaml
ENV HTTP_TRACER_LOG_LEVEL=info

# Add security labels
LABEL security.capabilities="CAP_SYS_ADMIN,CAP_BPF" \
      security.privileged="true" \
      maintainer="eBPF Tracer Team" \
      version="1.0.0"

# Run the tracer
ENTRYPOINT ["/app/tracer"]
CMD ["--config", "/app/config/default.yaml"]
