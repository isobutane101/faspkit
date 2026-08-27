# faspkit — a Fediverse Auxiliary Service Provider
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src ./src
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY bin ./bin

# Keys and state live here. Mount a volume, and back it up together with
# FASPKIT_SECRET — without that secret the stored keys cannot be read.
ENV FASPKIT_DATA=/data
VOLUME /data
EXPOSE 3000

# Run unprivileged; the node image ships a suitable user.
RUN mkdir -p /data && chown -R node:node /data
USER node

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "fetch('http://localhost:'+(process.env.PORT||3000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "bin/faspkit.js"]
