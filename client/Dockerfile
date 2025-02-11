FROM nginx:alpine
WORKDIR /usr/share/nginx/html
RUN rm -rf ./*
COPY ./dist/client/browser .
COPY ./nginx.conf /etc/nginx/conf.d/default.conf:ro

EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]