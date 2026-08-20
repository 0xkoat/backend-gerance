FROM node:22-slim AS builder

WORKDIR /app

COPY package*.json ./

RUN npm ci

COPY . .

RUN npx prisma generate

RUN npm run build

FROM node:22-slim AS runner

USER node

ENV NODE_ENV=production

WORKDIR /app

COPY --chown=node:node --from=builder /app/package*.json ./

COPY --chown=node:node --from=builder /app/dist/ ./dist/

COPY --chown=node:node --from=builder /app/prisma ./prisma/

COPY --chown=node:node --from=builder /app/prisma.config.ts ./prisma.config.ts

COPY --chown=node:node docker-entrypoint.sh ./docker-entrypoint.sh

RUN chmod +x ./docker-entrypoint.sh

RUN npm install --production && npm cache clean --force

EXPOSE 3000

ENTRYPOINT ["./docker-entrypoint.sh"]