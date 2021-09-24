#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:5.0 AS base
WORKDIR /app
EXPOSE 80
ENV ConnectionStrings:DefaultConnection="Server=IMCLBCP41-BLL\\SQLEXPRESS2019; Database=PMS; Trusted_Connection=True; MultipleActiveResultSets=true"
ENV ASPNETCORE_ENVIRONMENT="Production"
ENV Jwt:Secret="ByYM000OLlMQG6VVVp1OH7Xzyr7gHuw1qvUC5dcGt3SNM"
ENV Jwt:Issuer="http://localhost:44340"
ENV Jwt:Audience="http://localhost:4200"

FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build
WORKDIR /src
COPY ["JWTAuthentication.csproj", "."]
RUN dotnet restore "./JWTAuthentication.csproj"
COPY . .
WORKDIR "/src/."
RUN dotnet build "JWTAuthentication.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "JWTAuthentication.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "JWTAuthentication.dll"]