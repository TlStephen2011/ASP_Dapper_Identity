FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /app

ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:5000

# Copy published output from build stage
COPY  ./server-files .

# Expose the necessary port
EXPOSE 5000

# Start the app
CMD ["dotnet", "API_Identity.dll"]