FROM node:18
WORKDIR /app
COPY package.json ./
RUN npm install
COPY src/ ./src/
COPY .env ./
EXPOSE 3000
CMD ["node", "src/server.js"]