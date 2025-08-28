# Syntax: docker/dockerfile:1
FROM node:20-slim

WORKDIR /app
ENV NODE_ENV=production

# Install deps
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Copy source
COPY src ./src

# Cloud Run listens on $PORT
EXPOSE 8080
CMD ["npm", "start"]

