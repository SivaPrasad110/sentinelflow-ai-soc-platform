# ==============================================================================
# Stage 1: Builder — install deps and run Vite production build
# ==============================================================================
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
COPY packages/shared/package.json ./packages/shared/
COPY apps/web/package.json ./apps/web/

RUN npm ci --workspace=apps/web --workspace=packages/shared --ignore-scripts

COPY packages/shared/ ./packages/shared/
COPY apps/web/ ./apps/web/

# Build shared types, then Vite bundle
RUN npm run build --workspace=packages/shared 2>/dev/null || true
RUN npm run build --workspace=apps/web

# ==============================================================================
# Stage 2: NGINX static server
# ==============================================================================
FROM nginx:1.27-alpine AS runner

# Remove default NGINX config
RUN rm /etc/nginx/conf.d/default.conf

# Copy built SPA
COPY --from=builder /app/apps/web/dist /usr/share/nginx/html

# Copy custom NGINX config (SPA fallback + API proxy)
COPY nginx/app.conf /etc/nginx/conf.d/app.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
