# Use the same Node.js version as the server for consistency
FROM node:18

# Set working directory
WORKDIR /app

# Copy local package.json and install dependencies
COPY package.json ./
RUN npm install

# Copy the frequency poster script
COPY post_schumann_frequency.js ./

# Ensure the script is executable
RUN chmod +x post_schumann_frequency.js

# Run the script
CMD ["node", "post_schumann_frequency.js"]