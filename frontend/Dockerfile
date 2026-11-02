FROM node:22-alpine
WORKDIR /app
RUN chown node:node /app
COPY --chown=node:node frontend/package.json frontend/package-lock.json ./
USER node
RUN npm ci --no-audit --no-fund
COPY --chown=node:node frontend/ ./
ENV CICC_API_TARGET=http://api:8000
EXPOSE 5173
CMD ["npm", "run", "dev"]
