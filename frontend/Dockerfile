# Build stage
FROM node:18-alpine AS builder
WORKDIR /app
ARG REACT_APP_API_URL
ENV REACT_APP_API_URL=${REACT_APP_API_URL}
COPY package.json package-lock.json* yarn.lock* ./
RUN npm ci || npm install
COPY . .
RUN npm run build

# Nginx stage
FROM nginx:alpine
WORKDIR /usr/share/nginx/html
COPY --from=builder /app/build .
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
