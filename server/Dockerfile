FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY migrations ./migrations

ENV NODE_ENV=production
EXPOSE 8787

USER node
CMD ["node", "src/server.js"]
