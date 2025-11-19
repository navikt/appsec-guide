# AppSec Guide

API to help developers prioritize which security issues to fix first.

## Getting Started

### Prerequisites
- Java 21
- Gradle 8.x

### Environment Variables

- `NAIS_TOKEN_INTROSPECTION_ENDPOINT` - Token introspection endpoint URL (required)
- `NAIS_API_URL` - NAIS GraphQL API endpoint URL (required)
- `NAIS_API_TOKEN` - Bearer token for NAIS API authentication (required)

### Running the Application

```bash
export NAIS_TOKEN_INTROSPECTION_ENDPOINT="https://your-introspection-endpoint"
export NAIS_API_URL="https://console.nav.cloud.nais.io/query"
export NAIS_API_TOKEN="your-api-token"
./gradlew run
```

For local development, point to your local mock endpoints.

The application will start on `http://localhost:8080`

### Testing

```bash
./gradlew test
```

Tests use `TestAppContext` with mocked dependencies, requiring no external services or environment variables.

## API Endpoints

- `GET /isready` - Readiness probe
- `GET /isalive` - Liveness probe
- `GET /me` - Get current user's NAVident (requires Bearer token authentication)
- `GET /nais/teams/{teamSlug}/ingresses` - Get team applications and their ingress types

### Authentication

The `/me` endpoint requires a valid Bearer token in the Authorization header:

```bash
curl -H "Authorization: Bearer <your-token>" http://localhost:8080/me
```

The token is validated using the NAIS token introspection endpoint. A valid token must contain a `NAVident` claim.

