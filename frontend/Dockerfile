# Веб-интерфейс: сборка React в статические файлы, раздача через nginx.
# nginx же проксирует /api на контейнер api, поэтому браузер видит один адрес.
FROM node:20-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 80
