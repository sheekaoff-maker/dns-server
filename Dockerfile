FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

FROM node:22-alpine AS runner

WORKDIR /app
RUN addgroup -S dnssvc && adduser -S dnssvc -G dnssvc

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=builder /app/dist ./dist

# Port 53 requires root to bind; the process itself still runs unprivileged —
# grant only the one Linux capability it needs instead of running as root.
RUN apk add --no-cache libcap && \
    setcap 'cap_net_bind_service=+ep' "$(readlink -f "$(which node)")" && \
    apk del libcap

USER dnssvc

EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 8080/tcp

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:' + (process.env.HEALTH_PORT || 8080) + '/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "dist/server.js"]
