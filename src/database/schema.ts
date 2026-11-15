import { sql } from "drizzle-orm";
import {
  boolean,
  check,
  customType,
  foreignKey,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";
const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType: () => "bytea",
});

export const organizations = pgTable(
  "organizations",
  {
    id: uuid("id").primaryKey(),
    organizationId: uuid("organization_id").notNull().unique(),
    firstParty: boolean("first_party").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("organizations_one_first_party")
      .on(table.firstParty)
      .where(sql`${table.firstParty} = true`),
  ],
);

export const emailDomainSuffixes = pgTable("email_domain_suffixes", {
  id: uuid("id").primaryKey(),
  suffix: text("suffix").notNull().unique(),
  organizationId: uuid("organization_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const users = pgTable(
  "users",
  {
    id: uuid("id").primaryKey(),
    provider: text("provider").notNull(),
    upstreamIssuer: text("upstream_issuer").notNull(),
    upstreamSubject: text("upstream_subject").notNull(),
    email: text("email").notNull(),
    emailSuffixId: uuid("email_suffix_id").references(() => emailDomainSuffixes.id, { onDelete: "set null" }),
    studentId: text("student_id"),
    schoolDistrict: text("school_district"),
    disabled: boolean("disabled").notNull().default(false),
    displayName: text("display_name"),
    picture: bytea("picture"),
    pictureContentType: text("picture_content_type"),
    tokensValidAfter: timestamp("tokens_valid_after", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("users_upstream_identity_unique").on(
      table.provider,
      table.upstreamIssuer,
      table.upstreamSubject,
    ),
    index("users_email_idx").on(table.email),
  ],
);

export const oidcClients = pgTable(
  "oidc_clients",
  {
    clientId: text("client_id").primaryKey(),
    metadata: jsonb("metadata").notNull().$type<Record<string, unknown>>(),
    secretHash: text("secret_hash"),
    resources: jsonb("resources").notNull().$type<string[]>(),
    requireConsent: boolean("require_consent").notNull().default(true),
    filterMode: text("filter_mode").$type<"whitelist" | "blacklist" | null>(),
    filterContent: jsonb("filter_content").notNull().default([]).$type<string[]>(),
    permissionCatalogVersion: integer("permission_catalog_version").notNull().default(1),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    check(
      "oidc_clients_filter_mode_check",
      sql`${table.filterMode} in ('whitelist', 'blacklist') or ${table.filterMode} is null`,
    ),
  ],
);

export const oidcPermissions = pgTable(
  "oidc_permissions",
  {
    clientId: text("client_id")
      .notNull()
      .references(() => oidcClients.clientId, { onDelete: "cascade" }),
    permission: text("permission").notNull(),
    description: text("description").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [primaryKey({ columns: [table.clientId, table.permission] })],
);

export const userPermissions = pgTable(
  "user_permissions",
  {
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    applicationId: text("application_id")
      .notNull()
      .references(() => oidcClients.clientId, { onDelete: "cascade" }),
    permission: text("permission").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({ columns: [table.userId, table.applicationId, table.permission] }),
    index("user_permissions_application_idx").on(table.applicationId, table.userId),
  ],
);

export const defaultPermissions = pgTable(
  "default_permissions",
  {
    applicationId: text("application_id").notNull(),
    permission: text("permission").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({ columns: [table.applicationId, table.permission] }),
    foreignKey({
      columns: [table.applicationId, table.permission],
      foreignColumns: [oidcPermissions.clientId, oidcPermissions.permission],
      name: "default_permissions_catalog_fk",
    }).onDelete("cascade"),
  ],
);

export const userApplications = pgTable(
  "user_applications",
  {
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    applicationId: text("application_id")
      .notNull()
      .references(() => oidcClients.clientId, { onDelete: "cascade" }),
    firstLoginAt: timestamp("first_login_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({ columns: [table.userId, table.applicationId] }),
    index("user_applications_application_idx").on(table.applicationId, table.userId),
  ],
);

export const oidcClientOrganizations = pgTable(
  "oidc_client_organizations",
  {
    clientId: text("client_id")
      .notNull()
      .references(() => oidcClients.clientId, { onDelete: "cascade" }),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [primaryKey({ columns: [table.clientId, table.organizationId] })],
);

export const resourceServers = pgTable("resource_servers", {
  audience: text("audience").primaryKey(),
  name: text("name").notNull(),
  scopes: jsonb("scopes").notNull().$type<string[]>(),
  secretHash: text("secret_hash").notNull(),
  createdBy: uuid("created_by").references(() => users.id, { onDelete: "set null" }),
  backchannelLogoutUri: text("backchannel_logout_uri"),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const backchannelVerifications = pgTable("backchannel_verifications", {
  nonce: text("nonce").primaryKey(),
  audience: text("audience").notNull().references(() => resourceServers.audience, { onDelete: "cascade" }),
  challenge: text("challenge").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  validatedAt: timestamp("validated_at", { withTimezone: true }),
}, (table) => [index("backchannel_verifications_expires_at_idx").on(table.expiresAt)]);

export const authSessions = pgTable(
  "auth_sessions",
  {
    idHash: text("id_hash").primaryKey(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    authenticatedAt: timestamp("authenticated_at", { withTimezone: true }).notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (table) => [index("auth_sessions_expires_at_idx").on(table.expiresAt)],
);

export const authorizationRequests = pgTable(
  "authorization_requests",
  {
    id: uuid("id").primaryKey(),
    initialUri: text("initial_uri").notNull(),
    interactionHash: text("interaction_hash").notNull(),
    clientId: text("client_id")
      .notNull()
      .references(() => oidcClients.clientId, { onDelete: "cascade" }),
    redirectUri: text("redirect_uri").notNull(),
    scopes: jsonb("scopes").notNull().$type<string[]>(),
    resource: text("resource").notNull(),
    state: text("state").notNull(),
    nonce: text("nonce").notNull(),
    codeChallenge: text("code_challenge").notNull(),
    userId: uuid("user_id").references(() => users.id, { onDelete: "cascade" }),
    authenticatedAt: timestamp("authenticated_at", { withTimezone: true }),
    status: text("status").notNull().default("pending"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (table) => [index("authorization_requests_expires_at_idx").on(table.expiresAt)],
);

export const authorizationCodes = pgTable(
  "authorization_codes",
  {
    codeHash: text("code_hash").primaryKey(),
    requestId: uuid("request_id")
      .notNull()
      .references(() => authorizationRequests.id, { onDelete: "cascade" }),
    clientId: text("client_id")
      .notNull()
      .references(() => oidcClients.clientId, { onDelete: "cascade" }),
    redirectUri: text("redirect_uri").notNull(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    scopes: jsonb("scopes").notNull().$type<string[]>(),
    resource: text("resource").notNull(),
    nonce: text("nonce").notNull(),
    codeChallenge: text("code_challenge").notNull(),
    authenticatedAt: timestamp("authenticated_at", { withTimezone: true }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
  },
  (table) => [index("authorization_codes_expires_at_idx").on(table.expiresAt)],
);

export const authorizationSessions = pgTable(
  "authorization_sessions",
  {
    id: uuid("id").primaryKey(),
    clientId: text("client_id")
      .notNull()
      .references(() => oidcClients.clientId, { onDelete: "cascade" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    scopes: jsonb("scopes").notNull().$type<string[]>(),
    resource: text("resource").notNull(),
    authenticatedAt: timestamp("authenticated_at", { withTimezone: true }),
    accessTokenJti: text("access_token_jti").unique(),
    accessTokenExpiresAt: timestamp("access_token_expires_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    refreshExpiresAt: timestamp("refresh_expires_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (table) => [
    index("authorization_sessions_user_id_idx").on(table.userId),
    index("authorization_sessions_client_id_idx").on(table.clientId),
  ],
);

export const refreshTokens = pgTable(
  "refresh_tokens",
  {
    tokenHash: text("token_hash").primaryKey(),
    sessionId: uuid("session_id")
      .notNull()
      .references(() => authorizationSessions.id, { onDelete: "cascade" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
  },
  (table) => [
    index("refresh_tokens_session_id_idx").on(table.sessionId),
    uniqueIndex("refresh_tokens_current_session_idx").on(table.sessionId).where(sql`${table.consumedAt} is null`),
  ],
);

export const accessTokenRevocations = pgTable(
  "access_token_revocations",
  {
    jti: text("jti").primaryKey(),
    audience: text("audience").notNull(),
    validAfter: timestamp("valid_after", { withTimezone: true }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    nextAttemptAt: timestamp("next_attempt_at", { withTimezone: true }).notNull().defaultNow(),
    deliveredAt: timestamp("delivered_at", { withTimezone: true }),
  },
  (table) => [
    index("access_token_revocations_pending_idx").on(table.nextAttemptAt).where(sql`${table.deliveredAt} is null`),
    index("access_token_revocations_expires_at_idx").on(table.expiresAt),
  ],
);

export const authorizationConsents = pgTable(
  "authorization_consents",
  {
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    clientId: text("client_id")
      .notNull()
      .references(() => oidcClients.clientId, { onDelete: "cascade" }),
    scopes: jsonb("scopes").notNull().$type<string[]>(),
    resources: jsonb("resources").notNull().$type<string[]>(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [primaryKey({ columns: [table.userId, table.clientId] })],
);

export const upstreamAuthRequests = pgTable(
  "upstream_auth_requests",
  {
    state: text("state").primaryKey(),
    authorizationRequestId: uuid("authorization_request_id")
      .notNull()
      .references(() => authorizationRequests.id, { onDelete: "cascade" }),
    codeVerifier: text("code_verifier").notNull(),
    nonce: text("nonce").notNull(),
    microsoftAuthority: text("microsoft_authority"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (table) => [index("upstream_auth_requests_expires_at_idx").on(table.expiresAt)],
);
