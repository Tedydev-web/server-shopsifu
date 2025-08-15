# ==============================================
# SHOPIFU SERVER DOCKERFILE (PURE NODE.JS)
# ==============================================
# Multi-stage build for production optimization
# Target: High-performance, high-concurrency Node.js application

# ==============================================
# BUILDER STAGE
# ==============================================
FROM node:20-alpine AS builder

# Set build environment
ARG NODE_ENV=production
ENV NODE_ENV=${NODE_ENV}

# NPM optimization for faster builds
ENV NPM_CONFIG_CACHE=/tmp/npm-cache
ENV NPM_CONFIG_PREFER_OFFLINE=true
ENV NPM_CONFIG_AUDIT=false
ENV NPM_CONFIG_FUND=false

# Install build dependencies
RUN apk add --no-cache \
    make \
    g++ \
    python3 \
    && rm -rf /var/cache/apk/*

# Set working directory
WORKDIR /app

# Copy package files for dependency installation
COPY package*.json ./
COPY prisma ./prisma/

# Install ALL dependencies (including devDependencies) for build process
RUN npm ci --silent --ignore-scripts \
    && npm install -g prisma-json-types-generator \
    && npm run generate \
    && npm cache clean --force

# Copy source code and config files
COPY src ./src
COPY tsconfig*.json ./
COPY nest-cli.json ./
COPY .swcrc ./

# Build application using direct path to nest binary
RUN rm -rf dist \
    && PATH="$PATH:./node_modules/.bin" npx nest build \
    && npm prune --production

# ==============================================
# PRODUCTION STAGE
# ==============================================
FROM node:20-alpine AS production

# Set production environment
ARG NODE_ENV=production
ENV NODE_ENV=${NODE_ENV}

# Create non-root user for security
RUN addgroup -g 1001 -S nestjs \
    && adduser -S nestjs -u 1001

# Install runtime dependencies
RUN apk add --no-cache \
    dumb-init \
    curl \
    && rm -rf /var/cache/apk/*

# Set working directory
WORKDIR /app

# Copy built application from builder stage
COPY --from=builder --chown=nestjs:nestjs /app/dist ./dist
COPY --from=builder --chown=nestjs:nestjs /app/node_modules ./node_modules
COPY --from=builder --chown=nestjs:nestjs /app/package*.json ./

# Create necessary directories
RUN mkdir -p /app/logs /app/certs /app/upload /app/temp \
    && chown -R nestjs:nestjs /app

# Switch to non-root user
USER nestjs

# ==============================================
# RUNTIME CONFIGURATION
# ==============================================
# Node.js performance optimization
ENV NODE_OPTIONS="--max-old-space-size=18000 --enable-source-maps"
ENV UV_THREADPOOL_SIZE=48

# Application configuration
ENV PORT=3000
ENV HOST=0.0.0.0

# Health check configuration
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=5 \
    CMD curl -f http://localhost:3000/health || exit 1

# Expose port
EXPOSE 3000

# ==============================================
# ENTRYPOINT & COMMAND
# ==============================================
# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Start application with cluster mode for high performance
CMD ["node", "--max-old-space-size=18000", "dist/main.js"]

# ==============================================
# OCI LABELS (Container metadata)
# ==============================================
LABEL org.opencontainers.image.title="Shopsifu Server"
LABEL org.opencontainers.image.description="High-performance e-commerce backend server"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.vendor="Tedydev Web"
LABEL org.opencontainers.image.authors="Tedydev Web Team"
LABEL org.opencontainers.image.source="https://github.com/Tedydev-web/server-shopsifu"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.created="2025-01-27T00:00:00Z"
