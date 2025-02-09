FROM nginx:alpine
WORKDIR /usr/share/nginx/html
RUN rm -rf ./*
COPY ./client/browser .

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]