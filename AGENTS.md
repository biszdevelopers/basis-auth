# Repository Guidelines

## SETUP_GUIDE.md Is Mandatory

`SETUP_GUIDE.md` is the downstream integration contract for every project that
connects to basis-auth. **Any change to this repository that affects behavior,
configuration, endpoints, tokens, registration, or integration steps MUST update
`SETUP_GUIDE.md` in the same change. There are no exceptions.**

A pull request that changes logic without a matching `SETUP_GUIDE.md` update is
incomplete and must be rejected in review. Do not leave it for a follow-up.

Update the guide whenever you change any of:

- routes, discovery metadata, or endpoint behavior;
- token claims, `typ` values, lifetimes, signing, or validation requirements;
- authorization, consent, session, refresh, revocation, or logout behavior,
  including backchannel logout and access-token revocation events;
- scopes, permission definitions, defaults, grants, or their enforcement;
- client or resource registration fields, defaults, or validation rules;
- internal API authentication, headers, routes, or error behavior;
- error codes, response formats, or rejection semantics;
- environment variables, defaults, or required deployment configuration;
- CLI commands, scripts, migration requirements, or upgrade steps;
- `examples/` code, including the resource-server middleware;
- runtime requirements, dependencies, or supported platform versions.

Also update the guide when `README.md`, `.env.example`, or `docs/` changes in a
way that alters what a downstream project must do. Keep commands runnable,
examples current, and every claim aligned with the code. If an integration step
changes, update the affected section and the verification checklist.

## Project Structure & Module Organization

- `src/` contains the Hono/OIDC service. `app.ts` defines HTTP routes, `oauth/` contains protocol and token logic, `database/` contains Drizzle schema, migrations, and seeding, and `microsoft.ts` implements the upstream login flow.
- `web/` is the React/Vite interaction UI. Put application components in `web/src/components/`, reusable UI primitives in `web/src/components/ui/`, and browser-facing helpers in `web/src/lib/`.
- `drizzle/` holds generated SQL migrations and metadata. Do not edit historical migrations; generate a new one after schema changes.
- `scripts/` contains maintenance CLIs. `examples/` contains downstream integration examples.

## Build, Test, and Development Commands

- `bun run dev` builds the UI, watches the backend, and watches UI builds.
- `bun run dev:web` runs Vite’s development server for UI work.
- `bun run typecheck` checks both server and web TypeScript projects.
- `bun run build` creates the production web build and compiles server code to `dist/`.
- `bun run test` runs the Vitest suite; target a file with `bunx vitest run src/app.test.ts`.
- `bun run db:generate` creates a Drizzle migration after changing `src/database/schema.ts`; use `bun run db:migrate` to apply migrations with `DATABASE_URL` set.

## Coding Style & Naming Conventions

Use TypeScript with ESM imports and match the formatting of the surrounding file (server code generally uses two spaces; UI components currently use their local style). Use `camelCase` for functions and values, `PascalCase` for React components and exported types, and kebab-case filenames such as `scope-description.ts`. Keep route handlers focused; place OAuth or persistence rules in their respective service modules. Use existing shadcn-style primitives before adding new UI patterns.

## Testing Guidelines

Use Vitest for unit and route tests. Name tests as behavior statements, for example `it("redirects browser logout requests to the original authorization URL", ...)`. Add or update tests for authorization, token, identity, configuration, and migration-affecting behavior. PostgreSQL integration tests require a `DATABASE_URL` and `RUN_POSTGRES_TESTS=1`; they no longer need Docker.

## Commit & Pull Request Guidelines

Use concise, imperative Conventional Commit-style subjects, e.g. `feat: add client filtering` or `fix: preserve authorize query`. Keep commits scoped. Pull requests should explain the behavioral change, list validation commands, mention migrations or configuration changes, and include screenshots for visible UI changes.

## Security & Configuration

Never commit `.env`, credentials, private JWKs, tokens, or database dumps. Start from `.env.example`. Keep `OIDC_ISSUER`, the running port, and Microsoft redirect URI aligned. Treat OAuth redirect, session, consent, and token changes as security-sensitive and verify their failure paths.
