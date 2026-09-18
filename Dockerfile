# Naija Dimes Hub — Fly.io deploy
FROM node:22-bookworm

# Install build dependencies for native modules (better-sqlite3, bcrypt)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests first for better layer caching
COPY package.json package-lock.json* ./

# Install deps (better-sqlite3 builds native here)
RUN npm install --no-audit --no-fund

# Copy app source (data/ excluded via .dockerignore; persisted on disk at runtime)
COPY . .

# Ensure data dir exists
RUN mkdir -p /app/data/uploads

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["node", "server.js"]
