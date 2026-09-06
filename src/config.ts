import { readFile } from "node:fs/promises";
import { generateKeyPair, exportJWK, type JWK } from "jose";
import { z } from "zod";

export const clientSchema = z.object({
  clientId: z.string().min(1),
  name: z.string().min(1).optional(),
  clientSecret: z.string().min(16).optional(),
  redirectUris: z.array(z.url()).min(1),
  public: z.boolean().default(false),
  scopes: z.array(z.string().min(1)).default(["openid", "profile", "email"]),
  resources: z.array(z.string().min(1)).min(1),
  requireConsent: z.boolean().default(true),
  filterMode: z.enum(["whitelist", "blacklist"]).nullable().default(null),
  filterContent: z.array(z.string().min(1).transform((value) => value.trim().toLowerCase())).default([]),
});

export const clientInputSchema = clientSchema.omit({ clientId: true });

const resourceSchema = z.object({
  audience: z.string().min(1),
  scopes: z.array(z.string().min(1)).default([]),
});

const bootstrapGrantSchema = z.object({
  email: z.email().transform((email) => email.toLowerCase()),
  permissions: z.array(z.string().min(1)),
});

const optionalJsonArray = z.preprocess(
  (value) => value === "" ? undefined : value,
  z.string().default("[]"),
);

const environmentSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  DATABASE_URL: z.string().min(1),
  INTERNAL_API_HOST: z.string().min(1).default("127.0.0.1"),
  INTERNAL_API_PORT: z.coerce.number().int().positive().default(3001),
  INTERNAL_API_TOKEN: z.string().min(32),
  OIDC_ISSUER: z.url().transform((issuer) => issuer.replace(/\/$/, "")),
  OIDC_COOKIE_KEYS: z.string().min(32),
  OIDC_JWKS_JSON: z.string().optional(),
  OIDC_JWKS_FILE: z.string().optional(),
  OIDC_CLIENTS_JSON: optionalJsonArray,
  OIDC_RESOURCES_JSON: optionalJsonArray,
  DEFAULT_PERMISSION: z.string().min(1).default("participant"),
  BOOTSTRAP_PERMISSION_GRANTS_JSON: optionalJsonArray,
  MICROSOFT_ISSUER: z.url().optional(),
  MICROSOFT_CLIENT_ID: z.string().min(1).optional(),
  MICROSOFT_CLIENT_SECRET: z.string().min(1).optional(),
});

export type ClientSeed = z.infer<typeof clientSchema>;
export type ResourceSeed = z.infer<typeof resourceSchema>;
export type BootstrapPermissionGrant = z.infer<typeof bootstrapGrantSchema>;

export interface AppConfig {
  environment: "development" | "test" | "production";
  port: number;
  databaseUrl: string;
  internalApiHost: string;
  internalApiPort: number;
  internalApiToken: string;
  issuer: string;
  cookieKeys: string[];
  jwks: { keys: JWK[] };
  clients: ClientSeed[];
  resources: ResourceSeed[];
  defaultPermission: string;
  bootstrapPermissionGrants: BootstrapPermissionGrant[];
  microsoft?: {
    issuer: string;
    clientId: string;
    clientSecret: string;
  };
}

function parseJson<T>(name: string, value: string, schema: z.ZodType<T>): T {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${name} must contain valid JSON`);
  }
  return schema.parse(parsed);
}

async function loadJwks(env: z.infer<typeof environmentSchema>): Promise<{ keys: JWK[] }> {
  let raw = env.OIDC_JWKS_JSON;
  if (!raw && env.OIDC_JWKS_FILE) raw = await readFile(env.OIDC_JWKS_FILE, "utf8");

  if (raw) {
    return parseJson(
      "OIDC_JWKS_JSON",
      raw,
      z.object({ keys: z.array(z.record(z.string(), z.unknown())).min(1) }),
    ) as { keys: JWK[] };
  }

  if (env.NODE_ENV === "production") {
    throw new Error("OIDC_JWKS_JSON or OIDC_JWKS_FILE is required in production");
  }

  const { privateKey } = await generateKeyPair("RS256", { extractable: true });
  const jwk = await exportJWK(privateKey);
  jwk.use = "sig";
  jwk.alg = "RS256";
  jwk.kid = crypto.randomUUID();
  return { keys: [jwk] };
}

export async function loadConfig(source: NodeJS.ProcessEnv = process.env): Promise<AppConfig> {
  const env = environmentSchema.parse(source);
  const issuerUrl = new URL(env.OIDC_ISSUER);
  if (issuerUrl.pathname !== "/" || issuerUrl.search || issuerUrl.hash) {
    throw new Error("OIDC_ISSUER must be an origin without a path, query, or fragment");
  }
  const issuerHost = issuerUrl.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (env.NODE_ENV === "development" && issuerHost !== "localhost" && issuerHost !== "127.0.0.1" && issuerHost !== "::1") {
    throw new Error(
      `OIDC_ISSUER points at ${issuerHost} but NODE_ENV is development: development cookie settings ` +
        "(Domain=localhost) only work with a localhost issuer and browsers drop every session otherwise. " +
        "Set NODE_ENV=production with production secrets.",
    );
  }
  const microsoftValues = [
    env.MICROSOFT_ISSUER,
    env.MICROSOFT_CLIENT_ID,
    env.MICROSOFT_CLIENT_SECRET,
  ];
  const hasSomeMicrosoftConfig = microsoftValues.some(Boolean);
  const hasAllMicrosoftConfig = microsoftValues.every(Boolean);
  if (hasSomeMicrosoftConfig && !hasAllMicrosoftConfig) {
    throw new Error(
      "MICROSOFT_ISSUER, MICROSOFT_CLIENT_ID, and MICROSOFT_CLIENT_SECRET must be set together",
    );
  }
  if (env.NODE_ENV === "production" && !hasAllMicrosoftConfig) {
    throw new Error("Microsoft OIDC configuration is required in production");
  }

  const clients = parseJson("OIDC_CLIENTS_JSON", env.OIDC_CLIENTS_JSON, z.array(clientSchema));
  for (const client of clients) {
    if (client.public && client.clientSecret) {
      throw new Error(`Public client ${client.clientId} must not define a client secret`);
    }
    if (!client.public && !client.clientSecret) {
      throw new Error(`Confidential client ${client.clientId} requires a client secret`);
    }
    if (client.filterMode === null && client.filterContent.length > 0) {
      throw new Error(`Client ${client.clientId} requires filterMode when filterContent is set`);
    }
  }

  const resources = parseJson(
    "OIDC_RESOURCES_JSON",
    env.OIDC_RESOURCES_JSON,
    z.array(resourceSchema),
  );
  const knownResources = new Set(resources.map((resource) => resource.audience));
  for (const configuredClient of clients) {
    for (const resource of configuredClient.resources) {
      if (!knownResources.has(resource)) {
        throw new Error(`Client ${configuredClient.clientId} references unknown resource ${resource}`);
      }
    }
  }

  const cookieKeys = env.OIDC_COOKIE_KEYS.split(",").map((value) => value.trim());
  if (cookieKeys.some((key) => key.length < 32)) {
    throw new Error("Every OIDC cookie key must be at least 32 characters");
  }
  const placeholderPattern = /replace-with|changeme|change-me|your-.+-here|placeholder/i;
  if (cookieKeys.some((key) => placeholderPattern.test(key))) {
    throw new Error("OIDC_COOKIE_KEYS must be replaced with real randomly generated values");
  }
  if (env.NODE_ENV === "production" && cookieKeys.length < 2) {
    throw new Error("At least two OIDC cookie keys are required in production");
  }

  return {
    environment: env.NODE_ENV,
    port: env.PORT,
    databaseUrl: env.DATABASE_URL,
    internalApiHost: env.INTERNAL_API_HOST,
    internalApiPort: env.INTERNAL_API_PORT,
    internalApiToken: env.INTERNAL_API_TOKEN,
    issuer: env.OIDC_ISSUER,
    cookieKeys,
    jwks: await loadJwks(env),
    clients,
    resources,
    defaultPermission: env.DEFAULT_PERMISSION,
    bootstrapPermissionGrants: parseJson(
      "BOOTSTRAP_PERMISSION_GRANTS_JSON",
      env.BOOTSTRAP_PERMISSION_GRANTS_JSON,
      z.array(bootstrapGrantSchema),
    ),
    microsoft: hasAllMicrosoftConfig
      ? {
          issuer: env.MICROSOFT_ISSUER!,
          clientId: env.MICROSOFT_CLIENT_ID!,
          clientSecret: env.MICROSOFT_CLIENT_SECRET!,
        }
      : undefined,
  };
}
