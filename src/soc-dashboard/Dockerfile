# ─── Stage 1: Build the Vite bundle ──────────────────────────────────────────
FROM node:20-alpine AS build
WORKDIR /app

# Build-time env vars are baked into the JS bundle (Vite constraint).
# Production default: same-origin relative paths routed by Caddy.
ARG VITE_API_BASE_URL=/api/v1
ARG VITE_HUB_URL=/hubs/alerts
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL} \
    VITE_HUB_URL=${VITE_HUB_URL}

COPY soc_platform/src/soc-dashboard/package*.json ./
RUN npm ci --no-audit --no-fund

COPY soc_platform/src/soc-dashboard ./
RUN npm run build

# ─── Stage 2: Serve via nginx ────────────────────────────────────────────────
FROM nginx:1.27-alpine AS runtime

# Custom config handles SPA routing (fallback to index.html) + long-cache on assets.
COPY soc_platform/src/soc-dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost/ >/dev/null 2>&1 || exit 1
