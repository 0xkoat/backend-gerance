FROM node:22-slim AS builder

WORKDIR /app

COPY package*.json ./

RUN npm ci

COPY . .

RUN npx prisma generate

RUN npm run build

# --- migrator: runs `prisma migrate deploy` / `prisma db seed` / `npm run seed:demo` as a
# one-off job (see docker-compose.yml's `migrate`/`seed` services), never serves traffic.
# Reuses the builder's own `node_modules` as-is (a full `npm ci`, dev deps included) instead
# of a second install — same exact versions that were just built and tested, and avoids
# redownloading `prisma`/`ts-node`/`typescript`/`@faker-js/faker` a second time.
FROM node:22-slim AS migrator

USER node

ENV NODE_ENV=production

WORKDIR /app

COPY --chown=node:node --from=builder /app/node_modules ./node_modules/
COPY --chown=node:node --from=builder /app/package*.json ./
COPY --chown=node:node --from=builder /app/prisma ./prisma/

# migrate deploy reads datasource.url from here, not from schema.prisma's own
# datasource block (verified 2026-08-21: schema.prisma has no `url = env(...)`
# line — this project puts it in prisma.config.ts instead). It lives at the
# repo root next to prisma/, not inside it, so it needs its own COPY.
COPY --chown=node:node --from=builder /app/prisma.config.ts ./prisma.config.ts

# `npm run seed`/`seed:demo` run via ts-node, not through `nest build` — prisma/
# lives outside tsconfig's rootDir (src/), so it's never compiled into dist/.
# ts-node executes each script's exact source imports at face value (including
# `../src/generated/prisma/client`), so that generated client's TS source has
# to exist on disk here too, not just its compiled copy under dist/ — hence
# this COPY. tsconfig.json is also required: ts-node auto-discovers it by
# walking up from the file it runs, and prisma/tsconfig.json's own `extends:
# "../tsconfig.json"` depends on it being present at this exact path too.
COPY --chown=node:node --from=builder /app/src/generated/prisma ./src/generated/prisma/
COPY --chown=node:node --from=builder /app/tsconfig.json ./tsconfig.json

# No fixed ENTRYPOINT/CMD default beyond this — every real invocation supplies
# its own `command:` (see docker-compose.yml's `migrate`/`seed` services).
CMD ["npx", "prisma", "migrate", "deploy"]

# --- runner: the only stage that serves traffic. No Prisma CLI, no ts-node/typescript, no
# raw TS source, no migrations folder — none of it is needed to run the already-built
# `dist/main.js`, which talks to Postgres purely through `@prisma/client` +
# `@prisma/adapter-pg` (the WASM query compiler, see schema.prisma's own comment — no native
# schema-engine binary in this stage either, that's migrator-only).
FROM node:22-slim AS runner

USER node

ENV NODE_ENV=production

WORKDIR /app

COPY --chown=node:node --from=builder /app/package*.json ./

COPY --chown=node:node --from=builder /app/dist/ ./dist/

# --omit=dev alone isn't enough here: @prisma/client declares `prisma` and
# `typescript` as *optional peer* dependencies (verified via package-lock.json
# — peerDependenciesMeta marks both optional:true), and npm auto-installs
# satisfiable optional peers regardless of which package.json section they're
# listed in. --omit=optional is what actually excludes them from this stage.
RUN npm install --omit=dev --omit=optional && npm cache clean --force

EXPOSE 3000

CMD ["node", "dist/main.js"]
