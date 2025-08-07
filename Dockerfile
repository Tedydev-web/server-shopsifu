FROM node:20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache --virtual .build-deps \
    alpine-sdk \
    python3

# Set working directory
WORKDIR /app

# Copy package files
COPY package.json package-lock.json ./

# Install all dependencies (including devDependencies)
RUN npm ci

# Copy Prisma schema
COPY prisma ./prisma/

# Generate Prisma client
RUN npm run generate

# Copy source code
COPY . .

# Build dist
RUN npm run build

# Remove devDependencies and build deps
RUN npm prune --omit=dev && apk del .build-deps

FROM node:20-alpine AS production

# Set working directory
WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nestjs -u 1001

# Install @nestjs/cli globally for production
RUN npm install -g @nestjs/cli

# Copy built application from builder stage
COPY --from=builder /app/package.json ./
COPY --from=builder /app/package-lock.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/ecosystem.config.js ./
COPY --from=builder /app/prisma ./prisma

# Change ownership
RUN chown -R nestjs:nodejs /app
USER nestjs

# Expose port
EXPOSE 3000

# Start production server
CMD ["npm", "run", "start:pm2"]
