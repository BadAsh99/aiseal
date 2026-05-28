FROM node:20-alpine AS builder
WORKDIR /app

# Forward Railway service variables into the build stage.
# NEXT_PUBLIC_* vars get inlined into the client bundle at build time, so they
# MUST be present when `next build` runs. Railway passes them as Docker --build-arg
# but BuildKit only exposes them inside the build if we declare them with ARG.
# Without this, Railway's env vars never reach `next build` and the prerender
# of any page touching Supabase crashes with "SUPABASE env missing."
ARG NEXT_PUBLIC_SUPABASE_URL
ARG NEXT_PUBLIC_SUPABASE_ANON_KEY
ARG SUPABASE_SERVICE_ROLE_KEY
ARG AISEAL_BADGE_SECRET
ENV NEXT_PUBLIC_SUPABASE_URL=$NEXT_PUBLIC_SUPABASE_URL \
    NEXT_PUBLIC_SUPABASE_ANON_KEY=$NEXT_PUBLIC_SUPABASE_ANON_KEY \
    SUPABASE_SERVICE_ROLE_KEY=$SUPABASE_SERVICE_ROLE_KEY \
    AISEAL_BADGE_SECRET=$AISEAL_BADGE_SECRET

COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/server.js ./server.js
EXPOSE 3000
CMD ["node", "server.js"]
