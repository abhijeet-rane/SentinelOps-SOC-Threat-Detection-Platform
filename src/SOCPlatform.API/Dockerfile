# ─── Stage 1: Restore + Build ────────────────────────────────────────────────
# Mounts the whole solution so EF migrations and project references resolve.
# Build context is the repo root (../.. from this file) so every csproj is visible.
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src

# Copy just the solution + csprojs first so `dotnet restore` is cacheable.
COPY soc_platform/SOCPlatform.slnx soc_platform/
COPY soc_platform/src/SOCPlatform.Core/SOCPlatform.Core.csproj                      soc_platform/src/SOCPlatform.Core/
COPY soc_platform/src/SOCPlatform.Infrastructure/SOCPlatform.Infrastructure.csproj  soc_platform/src/SOCPlatform.Infrastructure/
COPY soc_platform/src/SOCPlatform.Detection/SOCPlatform.Detection.csproj            soc_platform/src/SOCPlatform.Detection/
COPY soc_platform/src/SOCPlatform.API/SOCPlatform.API.csproj                        soc_platform/src/SOCPlatform.API/
COPY soc_platform/src/SOCPlatform.AttackSim/SOCPlatform.AttackSim.csproj            soc_platform/src/SOCPlatform.AttackSim/
COPY soc_platform/src/SOCPlatform.Tests/SOCPlatform.Tests.csproj                    soc_platform/src/SOCPlatform.Tests/
COPY soc_platform/src/SOCPlatform.DesktopAgent/SOCPlatform.DesktopAgent.csproj      soc_platform/src/SOCPlatform.DesktopAgent/

RUN dotnet restore soc_platform/src/SOCPlatform.API/SOCPlatform.API.csproj

# Copy the rest of the source and publish self-contained to /app/publish.
COPY soc_platform/src/SOCPlatform.Core          soc_platform/src/SOCPlatform.Core
COPY soc_platform/src/SOCPlatform.Infrastructure soc_platform/src/SOCPlatform.Infrastructure
COPY soc_platform/src/SOCPlatform.Detection     soc_platform/src/SOCPlatform.Detection
COPY soc_platform/src/SOCPlatform.API           soc_platform/src/SOCPlatform.API

RUN dotnet publish soc_platform/src/SOCPlatform.API/SOCPlatform.API.csproj \
        -c Release \
        -o /app/publish \
        --no-restore \
        /p:UseAppHost=false

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
# Non-root user, small base image, listens on 8080 behind Caddy.
FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS runtime
WORKDIR /app

RUN addgroup -S soc && adduser -S soc -G soc \
    && apk add --no-cache curl icu-libs

# ICU is needed for globalization; Alpine ASPNET image ships without it by default.
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false \
    ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_RUNNING_IN_CONTAINER=true

COPY --from=build /app/publish .
RUN chown -R soc:soc /app
USER soc

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS http://localhost:8080/health/live || exit 1

ENTRYPOINT ["dotnet", "SOCPlatform.API.dll"]
