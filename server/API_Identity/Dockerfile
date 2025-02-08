# Build Stage
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy only .csproj files first (for caching)
COPY API_Identity/API_Identity.csproj API_Identity/
COPY API_Common/API_Common.csproj API_Common/

# Restore dependencies
RUN dotnet restore API_Identity/API_Identity.csproj

# Copy all other files
COPY . ./

# Build and publish
RUN dotnet publish API_Identity/API_Identity.csproj -c Release -o /publish --no-restore

# Runtime Stage
# FROM mcr.microsoft.com/dotnet/aspnet:9.0
# WORKDIR /app

# # Copy published output from build stage
# COPY --from=build /publish .

# # Expose the necessary port
# EXPOSE 5000

# # Start the app
# CMD ["dotnet", "API_Identity.dll"]
