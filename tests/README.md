# SentinelFlow Integration and E2E Tests

This directory houses the integration and end-to-end test suites for the SentinelFlow platform.

## Test Structure

- `tests/integration/`: Tests verifying interactions between NestJS REST controllers, service layers, Prisma ORM, and database queries.
- `tests/e2e/`: Full-journey tests verifying API endpoints, webhook reception, and end-to-end incident ingestion to frontend consumption.

## Prerequisites

1. Ensure the backend dependencies are installed (`npm install`).
2. Run database migrations (`npm --workspace=@sentinelflow/api run prisma:migrate`) or run in mock mode.
3. Start the test suite:
   ```bash
   npm run test
   ```
