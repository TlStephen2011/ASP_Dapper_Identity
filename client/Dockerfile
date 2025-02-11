# Use the official Nginx image
FROM nginx:alpine

# Set the working directory
WORKDIR /usr/share/nginx/html

# Remove the default static files (optional)
RUN rm -rf ./*

# Copy built Angular app (assumes it's in ./dist/client/browser)
COPY ./dist/client/browser ./

# Remove the default Nginx config
RUN rm -rf /etc/nginx/conf.d/default.conf

# Copy your custom Nginx configuration
COPY ./nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80 inside the container
EXPOSE 8080

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]