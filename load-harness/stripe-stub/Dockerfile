# Passthrough Stripe stub for Tide load tests. Build from load-harness/stripe-stub.
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --no-audit --no-fund
COPY src ./src
RUN npx esbuild src/main.ts --bundle --platform=node --format=esm --target=node20 --outfile=dist/main.js

FROM node:20-alpine
WORKDIR /app
COPY --from=build /app/dist/main.js ./main.js
ENV PORT=8090 STRIPE_UPSTREAM=https://api.stripe.com STUB_EMAIL_SUFFIX=@invalid.tide.test
# Mount a volume and set STUB_STATE_FILE=/data/state.json to keep test workspaces across restarts.
EXPOSE 8090
USER node
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:${PORT}/__stub/health || exit 1
CMD ["node", "main.js"]
