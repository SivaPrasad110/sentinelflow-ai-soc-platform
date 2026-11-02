# ==============================================================================
# Stage 1: Builder — install dependencies and compile TypeScript
# ==============================================================================
FROM node:20-alpine AS builder

WORKDIR /app

# Install all workspace deps (monorepo root + api + shared)
COPY package.json package-lock.json ./
COPY packages/shared/package.json ./packages/shared/
COPY apps/api/package.json ./apps/api/

RUN npm ci --workspace=apps/api --workspace=packages/shared --ignore-scripts

# Copy source files
COPY packages/shared/ ./packages/shared/
COPY apps/api/ ./apps/api/

# Build shared package first, then API
RUN npm run build --workspace=packages/shared 2>/dev/null || true
RUN npm run build --workspace=apps/api

# ==============================================================================
# Stage 2: Production runner — minimal image, no dev tooling
# ==============================================================================
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

# Install production-only deps
COPY package.json package-lock.json ./
COPY packages/shared/package.json ./packages/shared/
COPY apps/api/package.json ./apps/api/

RUN npm ci --workspace=apps/api --workspace=packages/shared \
    --omit=dev --ignore-scripts \
  && npm cache clean --force

# Copy compiled output and Prisma schema
COPY --from=builder /app/apps/api/dist ./apps/api/dist
COPY --from=builder /app/apps/api/prisma ./apps/api/prisma
COPY --from=builder /app/packages/shared/dist ./packages/shared/dist 2>/dev/null || true

# Non-root user for security
RUN addgroup -S sentinelflow && adduser -S -G sentinelflow sentinelflow
USER sentinelflow

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/v1/health || exit 1

# Run Prisma migrations then start the server
CMD ["sh", "-c", "cd apps/api && npx prisma migrate deploy --schema=./prisma/schema.prisma && node dist/src/main"]
