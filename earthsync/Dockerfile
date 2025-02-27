# Use the official Node.js 16 image as the base
FROM node:16

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json (if present) to leverage caching
COPY package.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY src/ ./src/
COPY .env ./

# Expose the port the app runs on (default is 3000, configurable via .env)
EXPOSE 3000

# Command to run the application
CMD ["npm", "start"]