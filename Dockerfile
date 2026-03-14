# Stage 1: Build React client
FROM node:22-alpine AS client-build
WORKDIR /app/client
COPY client/package.json client/package-lock.json* ./
RUN npm ci
COPY client/ ./
RUN npm run build

# Stage 2: Production
FROM node:22-alpine
WORKDIR /app

# Install Trivy
RUN apk add --no-cache curl \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && trivy --version

# Install server dependencies
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Copy server code
COPY server.js scanner.js ./

# Copy built React app from stage 1
COPY --from=client-build /app/public ./public

# Create results directory
RUN mkdir -p /app/results

EXPOSE 4000

CMD ["node", "server.js"]
