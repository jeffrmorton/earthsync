FROM node:18.20.7-alpine AS base

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 3000

CMD ["node", "server.js"]
