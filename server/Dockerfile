FROM node:18.20.7 AS builder

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . ./

FROM node:18.20.7

WORKDIR /app

COPY --from=builder /app /app

RUN useradd -m postgres || true
USER postgres

EXPOSE 3000

CMD ["npm", "start"]
