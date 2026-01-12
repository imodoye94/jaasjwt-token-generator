FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev
COPY index.js ./
ENV PORT=8080
EXPOSE 8080
CMD ["npx","@google-cloud/functions-framework","--target=jaasjwt","--port=8080"]
