# Use the official Node.js image
FROM node:16-alpine

# Set the working directory in the container
WORKDIR /app

# Copy package.json and install dependencies
COPY package.json ./


RUN npm install

# Copy the rest of the application code
COPY . .


# Expose the port the app will run on
EXPOSE 3000

# Start the server
CMD ["npm", "start"]
