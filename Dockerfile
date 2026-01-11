# Runtime-only Dockerfile for grincel
# Binaries are cross-compiled on macOS and copied in

FROM alpine:3.21

ARG TARGETARCH

# Install Vulkan runtime
RUN apk add --no-cache vulkan-loader mesa-vulkan-swrast && \
    if [ "${TARGETARCH}" = "amd64" ]; then \
        apk add --no-cache mesa-vulkan-ati mesa-vulkan-intel || true; \
    elif [ "${TARGETARCH}" = "arm64" ]; then \
        apk add --no-cache mesa-vulkan-broadcom mesa-vulkan-freedreno mesa-vulkan-panfrost || true; \
    fi

# Copy pre-built binary (provided via build context)
COPY grincel /usr/local/bin/grincel
RUN chmod +x /usr/local/bin/grincel

ENTRYPOINT ["grincel"]
CMD ["--help"]
