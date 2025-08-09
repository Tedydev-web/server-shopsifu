# syntax=docker/dockerfile:1.7
FROM node:20-alpine AS builder

ENV NODE_ENV=development \
    HUSKY=0 \
    HUSKY_SKIP_INSTALL=1

# Install build dependencies
RUN apk add --no-cache --virtual .build-deps \
    alpine-sdk \
    python3

# Set working directory
WORKDIR /app

# Copy package files
COPY package.json package-lock.json ./

# Install all dependencies (including devDependencies)
RUN --mount=type=cache,target=/root/.npm \
    --mount=type=cache,target=/root/.cache/node-gyp \
    npm ci --include=dev --prefer-offline --no-audit --no-fund --loglevel=error

# Copy Prisma schema
COPY prisma ./prisma/

# Generate Prisma client
RUN --mount=type=cache,target=/root/.cache/prisma npm run generate

# Copy source code
COPY . .

# Build dist
RUN NODE_OPTIONS="--max-old-space-size=4096" npm run build

# Remove devDependencies and build deps
RUN npm prune --omit=dev && npm cache clean --force && apk del .build-deps

FROM node:20-alpine AS production

LABEL org.opencontainers.image.title="server-shopsifu" \
      org.opencontainers.image.source="https://github.com/Tedydev-web/server-shopsifu" \
      org.opencontainers.image.description="Shopsifu backend (NestJS) production image" \
      org.opencontainers.image.licenses="Proprietary"

ENV NODE_ENV=production \
    TZ=Asia/Ho_Chi_Minh \
    PRISMA_CLIENT_ENGINE_TYPE=library \
    PRISMA_HIDE_UPDATE_MESSAGE=1

# Set working directory
WORKDIR /app

# Install minimal runtime deps and create non-root user
RUN apk add --no-cache \
      curl \
      tzdata \
      openssl \
      libc6-compat \
  && addgroup -g 1001 -S nodejs \
  && adduser -S nestjs -u 1001 \
  && npm install -g pm2@latest

# Copy built application from builder stage (with correct ownership)
COPY --chown=nestjs:nodejs --from=builder /app/package.json ./
COPY --chown=nestjs:nodejs --from=builder /app/package-lock.json ./
COPY --chown=nestjs:nodejs --from=builder /app/node_modules ./node_modules
COPY --chown=nestjs:nodejs --from=builder /app/dist ./dist
COPY --chown=nestjs:nodejs --from=builder /app/ecosystem.config.js ./
COPY --chown=nestjs:nodejs --from=builder /app/prisma ./prisma
COPY --chown=nestjs:nodejs --from=builder /app/src/shared/languages ./src/shared/languages

USER nestjs

# Expose port
EXPOSE 3000

# Healthcheck (đồng nhất với compose)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:3000/health || exit 1

# Start production server
CMD ["pm2-runtime", "ecosystem.config.js"]
