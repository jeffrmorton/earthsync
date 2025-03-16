FROM node:18.20.7 AS builder

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . ./

FROM node:18.20.7

WORKDIR /app

COPY --from=builder /app /app

USER node

EXPOSE 3000

CMD ["npm", "start"]
