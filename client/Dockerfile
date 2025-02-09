FROM nginx:alpine
WORKDIR /usr/share/nginx/html
RUN rm -rf ./*
COPY ./client/browser .
COPY ./client/nginx.conf /etc/nginx/conf.d/default.conf:ro

EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]