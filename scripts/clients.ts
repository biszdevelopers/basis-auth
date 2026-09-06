import "dotenv/config";
import { randomBytes } from "node:crypto";
import { stdin as input, stdout as output } from "node:process";
import { createInterface, type Interface } from "node:readline/promises";
import { eq } from "drizzle-orm";
import { clientInputSchema, type ClientSeed } from "../src/config.js";
import { createDatabase, type Database } from "../src/database/client.js";
import {
  hashClientSecret,
  seedConfiguration,
  type ClientOwner,
  type StoredClientMetadata,
} from "../src/database/seed.js";
import { oidcClients, resourceServers } from "../src/database/schema.js";

// ponytail: stdlib readline TUI; no prompt dependency.
// Runtime visibility (see src/oauth/service.ts, src/oauth/clientCache.ts):
// new clients register instantly (cache misses aren't cached), client edits
// land within the 60s client-cache TTL, and resource_servers rows are read
// live per authorize request — so writes here need no restart.

export function generateClientSecret(): string {
  return `sk-${randomBytes(32).toString("hex")}`;
}

export function splitList(value: string): string[] {
  return value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

export function requireDatabase() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
  return createDatabase(process.env.DATABASE_URL);
}

function requireTty(): void {
  if (!process.stdin.isTTY) {
    throw new Error("This command needs an interactive terminal; pass arguments instead (see README).");
  }
}

async function ask(rl: Interface, question: string, defaultValue = ""): Promise<string> {
  const answer = (await rl.question(defaultValue ? `${question} [${defaultValue}]: ` : `${question}: `)).trim();
  return answer || defaultValue;
}

async function askYesNo(rl: Interface, question: string, defaultYes: boolean): Promise<boolean> {
  const answer = (await ask(rl, `${question} (${defaultYes ? "Y/n" : "y/N"})`)).toLowerCase();
  if (!answer) return defaultYes;
  return answer.startsWith("y");
}

export interface ListedClient {
  clientId: string;
  name: string;
  public: boolean;
  redirectUris: string[];
  resources: string[];
}

export async function listClients(db: Database): Promise<ListedClient[]> {
  const rows = await db.select().from(oidcClients);
  return rows
    .map((row) => {
      const metadata = row.metadata as Partial<StoredClientMetadata>;
      return {
        clientId: row.clientId,
        name: metadata.name || row.clientId,
        public: metadata.public ?? row.secretHash === null,
        redirectUris: metadata.redirectUris ?? [],
        resources: row.resources ?? [],
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

export async function deleteClientById(db: Database, clientId: string): Promise<string> {
  const removed = await db
    .delete(oidcClients)
    .where(eq(oidcClients.clientId, clientId))
    .returning({ clientId: oidcClients.clientId });
  if (!removed.length) throw new Error(`Client ${clientId} does not exist`);
  return removed[0]!.clientId;
}

export function printClients(clients: ListedClient[], known: Set<string>): void {
  if (!clients.length) {
    process.stdout.write("No clients registered.\n");
    return;
  }
  clients.forEach((client, index) => {
    process.stdout.write(`${index + 1}) ${client.name} (${client.clientId})${client.public ? " [public]" : ""}\n`);
    if (client.redirectUris.length) process.stdout.write(`   redirects: ${client.redirectUris.join(", ")}\n`);
    if (client.resources.length) process.stdout.write(`   resources: ${client.resources.join(", ")}\n`);
    const missing = client.resources.filter((audience) => !known.has(audience));
    if (missing.length) {
      process.stdout.write(
        `   WARNING: not registered as resource servers: ${missing.join(", ")} — re-save via Edit to register live\n`,
      );
    }
  });
}

async function resourceAudiences(db: Database): Promise<Set<string>> {
  const rows = await db.select({ audience: resourceServers.audience }).from(resourceServers);
  return new Set(rows.map((row) => row.audience));
}

// A client referencing an unregistered audience fails authorize with
// unknown_resource (14407). Insert-only: existing rows keep their scopes.
export async function ensureResourcesRegistered(
  db: Database,
  registrations: { audience: string; scopes: string[] }[],
): Promise<string[]> {
  if (!registrations.length) return [];
  const existing = await db.select({ audience: resourceServers.audience }).from(resourceServers);
  const known = new Set(existing.map((row) => row.audience));
  const missing = registrations.filter((reg) => !known.has(reg.audience));
  for (const reg of missing) {
    await db
      .insert(resourceServers)
      .values({ audience: reg.audience, scopes: reg.scopes })
      .onConflictDoNothing({ target: resourceServers.audience });
  }
  return missing.map((reg) => reg.audience);
}

export async function saveClient(
  db: Database,
  input: Omit<ClientSeed, "clientId">,
  resourceScopes: Map<string, string[]> = new Map(),
): Promise<ClientSeed> {
  await ensureResourcesRegistered(
    db,
    input.resources.map((audience) => ({ audience, scopes: resourceScopes.get(audience) ?? [] })),
  );
  const client: ClientSeed = { ...input, clientId: crypto.randomUUID() };
  await seedConfiguration(db, [client], []);
  return client;
}

async function promptRedirectUris(rl: Interface, initial: string): Promise<string[]> {
  for (;;) {
    const candidates = splitList(await ask(rl, "Redirect URIs (comma-separated)", initial));
    const invalid = candidates.filter((uri) => {
      try {
        new URL(uri);
        return false;
      } catch {
        return true;
      }
    });
    if (!candidates.length) process.stdout.write("At least one redirect URI is required.\n");
    else if (invalid.length) process.stdout.write(`Invalid URL(s): ${invalid.join(", ")}\n`);
    else return candidates;
  }
}

async function promptResources(rl: Interface, audiences: string[], initial: string): Promise<string[]> {
  if (audiences.length) {
    process.stdout.write("Registered resources:\n");
    audiences.forEach((audience, index) => process.stdout.write(`  ${index + 1}) ${audience}\n`));
  }
  for (;;) {
    const resources = splitList(await ask(rl, "Resources (comma-separated numbers or values)", initial)).map(
      (entry) => {
        const byNumber = /^\d+$/.test(entry) ? audiences[Number(entry) - 1] : undefined;
        return byNumber ?? entry;
      },
    );
    if (!resources.length) process.stdout.write("At least one resource is required.\n");
    else return resources;
  }
}

async function promptFilterMode(rl: Interface, initial: string): Promise<"whitelist" | "blacklist" | null> {
  for (;;) {
    const raw = (await ask(rl, "Account filter (blank, whitelist, blacklist)", initial)).toLowerCase();
    if (!raw) return null;
    if (raw === "whitelist" || raw === "blacklist") return raw;
    process.stdout.write('Enter blank, "whitelist", or "blacklist".\n');
  }
}

async function promptMissingResourceScopes(
  rl: Interface,
  resources: string[],
  known: Set<string>,
): Promise<Map<string, string[]>> {
  const scopes = new Map<string, string[]>();
  for (const audience of resources) {
    if (known.has(audience)) continue;
    process.stdout.write(`Resource ${audience} is not registered yet and will be created live.\n`);
    scopes.set(audience, splitList(await ask(rl, `Scopes for ${audience} (comma-separated, blank = none)`)));
  }
  return scopes;
}

function printClientSummary(input: {
  name?: string;
  public: boolean;
  redirectUris: string[];
  resources: string[];
  scopes: string[];
  requireConsent: boolean;
  filterMode: "whitelist" | "blacklist" | null;
  filterContent: string[];
}): void {
  process.stdout.write(
    `\nName: ${input.name ?? "(none)"}\nType: ${input.public ? "public" : "confidential"}\n` +
      `Redirects: ${input.redirectUris.join(", ")}\nResources: ${input.resources.join(", ")}\n` +
      `Scopes: ${input.scopes.join(", ")}\nConsent: ${input.requireConsent ? "shown" : "skipped"}\n` +
      `Filter: ${input.filterMode ?? "none"}${input.filterContent.length ? ` (${input.filterContent.join(", ")})` : ""}\n`,
  );
}

export interface NewClient {
  input: Omit<ClientSeed, "clientId">;
  generatedSecret: string | null;
  resourceScopes: Map<string, string[]>;
}

export async function promptNewClient(rl: Interface, audiences: string[]): Promise<NewClient | null> {
  const name = await ask(rl, "Display name");
  const isPublic = await askYesNo(rl, "Public client (no secret)?", false);

  let clientSecret: string | undefined;
  let generatedSecret: string | null = null;
  if (!isPublic) {
    const provided = await ask(rl, "Client secret (blank = auto-generate sk-...)");
    if (provided && provided.length < 16) throw new Error("Client secret must be at least 16 characters");
    clientSecret = provided || (generatedSecret = generateClientSecret());
  }

  const redirectUris = await promptRedirectUris(rl, "");
  const resources = await promptResources(rl, audiences, "");
  const resourceScopes = await promptMissingResourceScopes(rl, resources, new Set(audiences));

  const scopes = splitList(await ask(rl, "Scopes (comma-separated)", "openid, profile, email"));
  const requireConsent = await askYesNo(rl, "Show consent screen?", true);
  const filterMode = await promptFilterMode(rl, "");
  const filterContent = filterMode ? splitList(await ask(rl, "Filter emails (comma-separated)")) : [];

  const input = clientInputSchema.parse({
    ...(name ? { name } : {}),
    ...(clientSecret ? { clientSecret } : {}),
    redirectUris,
    public: isPublic,
    ...(scopes.length ? { scopes } : {}),
    resources,
    requireConsent,
    filterMode,
    filterContent,
  });

  printClientSummary(input);
  if (!(await askYesNo(rl, "Create this client?", true))) return null;
  return { input, generatedSecret, resourceScopes };
}

export async function runAddFlow(db: Database): Promise<void> {
  requireTty();
  const known = await resourceAudiences(db);
  const rl = createInterface({ input, output });
  try {
    const created = await promptNewClient(rl, [...known].sort());
    if (!created) {
      process.stdout.write("Cancelled.\n");
      return;
    }
    const client = await saveClient(db, created.input, created.resourceScopes);
    process.stdout.write(`Created client ${client.clientId}\n`);
    const registered = created.input.resources.filter((audience) => !known.has(audience));
    if (registered.length) {
      process.stdout.write(`Registered new resource(s) live, no restart needed: ${registered.join(", ")}\n`);
    }
    if (created.generatedSecret) {
      process.stdout.write(`Client secret (copy now, only a hash is stored): ${created.generatedSecret}\n`);
    }
  } finally {
    rl.close();
  }
}

async function pickClient(rl: Interface, clients: ListedClient[], verb: string): Promise<ListedClient> {
  const raw = await ask(rl, `Client to ${verb} (number or id)`);
  const byNumber = /^\d+$/.test(raw) ? clients[Number(raw) - 1] : undefined;
  const selected = byNumber ?? clients.find((client) => client.clientId === raw);
  if (!selected) throw new Error(`No client matches "${raw}"`);
  return selected;
}

async function listedOrEmpty(db: Database): Promise<ListedClient[] | null> {
  const clients = await listClients(db);
  if (!clients.length) {
    process.stdout.write("No clients registered.\n");
    return null;
  }
  printClients(clients, await resourceAudiences(db));
  return clients;
}

export async function runRemoveFlow(db: Database, preselected?: string): Promise<void> {
  if (preselected) {
    process.stdout.write(`${await deleteClientById(db, preselected)}\n`);
    return;
  }
  requireTty();
  const clients = await listedOrEmpty(db);
  if (!clients) return;
  const rl = createInterface({ input, output });
  try {
    const selected = await pickClient(rl, clients, "remove");
    if (
      !(await askYesNo(
        rl,
        `Delete ${selected.name} (${selected.clientId})? Authorization data goes with it`,
        false,
      ))
    ) {
      process.stdout.write("Cancelled.\n");
      return;
    }
    process.stdout.write(`${await deleteClientById(db, selected.clientId)}\n`);
  } finally {
    rl.close();
  }
}

export interface ClientDetail {
  clientId: string;
  name: string;
  public: boolean;
  hasSecret: boolean;
  redirectUris: string[];
  scopes: string[];
  resources: string[];
  requireConsent: boolean;
  filterMode: "whitelist" | "blacklist" | null;
  filterContent: string[];
  owners: ClientOwner[];
}

export async function getClientDetail(db: Database, clientId: string): Promise<ClientDetail> {
  const [row] = await db.select().from(oidcClients).where(eq(oidcClients.clientId, clientId)).limit(1);
  if (!row) throw new Error(`Client ${clientId} does not exist`);
  const metadata = row.metadata as Partial<StoredClientMetadata>;
  return {
    clientId: row.clientId,
    name: metadata.name || row.clientId,
    public: metadata.public ?? row.secretHash === null,
    hasSecret: row.secretHash !== null,
    redirectUris: metadata.redirectUris ?? [],
    scopes: metadata.scopes ?? [],
    resources: row.resources ?? [],
    requireConsent: row.requireConsent,
    filterMode: row.filterMode ?? null,
    filterContent: row.filterContent ?? [],
    owners: metadata.owners ?? [],
  };
}

export interface EditedClient {
  name: string;
  public: boolean;
  newSecret: string | null | undefined;
  redirectUris: string[];
  scopes: string[];
  resources: string[];
  requireConsent: boolean;
  filterMode: "whitelist" | "blacklist" | null;
  filterContent: string[];
  resourceScopes: Map<string, string[]>;
}

export async function promptEditClient(
  rl: Interface,
  current: ClientDetail,
  audiences: string[],
): Promise<EditedClient | null> {
  const name = await ask(rl, "Display name", current.name);
  const isPublic = await askYesNo(rl, "Public client (no secret)?", current.public);

  let newSecret: string | null | undefined;
  if (isPublic) {
    if (!current.public) process.stdout.write("The existing secret will be dropped.\n");
    newSecret = null;
  } else if (current.public || !current.hasSecret) {
    const provided = await ask(rl, "Client secret (blank = auto-generate sk-...)");
    if (provided && provided.length < 16) throw new Error("Client secret must be at least 16 characters");
    newSecret = provided || generateClientSecret();
  } else if (await askYesNo(rl, "Rotate secret?", false)) {
    const provided = await ask(rl, "New secret (blank = auto-generate sk-...)");
    if (provided && provided.length < 16) throw new Error("Client secret must be at least 16 characters");
    newSecret = provided || generateClientSecret();
  }

  const redirectUris = await promptRedirectUris(rl, current.redirectUris.join(", "));
  const resources = await promptResources(rl, audiences, current.resources.join(", "));
  const resourceScopes = await promptMissingResourceScopes(rl, resources, new Set(audiences));

  const scopesRaw = await ask(rl, "Scopes (comma-separated, blank = keep)", current.scopes.join(", "));
  const scopes = scopesRaw === current.scopes.join(", ") ? current.scopes : splitList(scopesRaw);
  const requireConsent = await askYesNo(rl, "Show consent screen?", current.requireConsent);
  const filterMode = await promptFilterMode(rl, current.filterMode ?? "");
  const filterDefault = filterMode === current.filterMode ? current.filterContent.join(", ") : "";
  const filterContent = filterMode ? splitList(await ask(rl, "Filter emails (comma-separated)", filterDefault)) : [];

  const input = clientInputSchema.parse({
    name,
    ...(typeof newSecret === "string" ? { clientSecret: newSecret } : {}),
    redirectUris,
    public: isPublic,
    scopes,
    resources,
    requireConsent,
    filterMode,
    filterContent,
  });

  printClientSummary(input);
  process.stdout.write(
    `Secret: ${newSecret === undefined ? "kept" : newSecret === null ? "dropped" : "rotated (shown once after save)"}\n`,
  );
  if (!(await askYesNo(rl, "Save changes?", true))) return null;
  return { ...input, name: input.name ?? current.clientId, newSecret, resourceScopes };
}

export async function applyClientEdit(db: Database, clientId: string, edit: EditedClient): Promise<string | null> {
  const [row] = await db.select().from(oidcClients).where(eq(oidcClients.clientId, clientId)).limit(1);
  if (!row) throw new Error(`Client ${clientId} does not exist`);
  const current = row.metadata as Partial<StoredClientMetadata>;
  const metadata = {
    ...current,
    name: edit.name,
    redirectUris: edit.redirectUris,
    public: edit.public,
    scopes: edit.scopes,
  };

  let secretHash = row.secretHash;
  let rotatedSecret: string | null = null;
  if (edit.newSecret === null) secretHash = null;
  else if (edit.newSecret !== undefined) {
    rotatedSecret = edit.newSecret;
    secretHash = await hashClientSecret(edit.newSecret);
  }

  await ensureResourcesRegistered(
    db,
    edit.resources.map((audience) => ({ audience, scopes: edit.resourceScopes.get(audience) ?? [] })),
  );
  await db
    .update(oidcClients)
    .set({
      metadata,
      secretHash,
      resources: edit.resources,
      requireConsent: edit.requireConsent,
      filterMode: edit.filterMode,
      filterContent: edit.filterContent,
      updatedAt: new Date(),
    })
    .where(eq(oidcClients.clientId, clientId));
  return rotatedSecret;
}

export async function runEditFlow(db: Database): Promise<void> {
  requireTty();
  const clients = await listedOrEmpty(db);
  if (!clients) return;
  const known = await resourceAudiences(db);
  const rl = createInterface({ input, output });
  try {
    const selected = await pickClient(rl, clients, "edit");
    const edited = await promptEditClient(rl, await getClientDetail(db, selected.clientId), [...known].sort());
    if (!edited) {
      process.stdout.write("Cancelled.\n");
      return;
    }
    const rotatedSecret = await applyClientEdit(db, selected.clientId, edited);
    process.stdout.write(`Updated client ${selected.clientId} (applies within ~60s, no restart needed)\n`);
    const registered = edited.resources.filter((audience) => !known.has(audience));
    if (registered.length) {
      process.stdout.write(`Registered new resource(s) live, no restart needed: ${registered.join(", ")}\n`);
    }
    if (rotatedSecret) {
      process.stdout.write(`New client secret (copy now, only a hash is stored): ${rotatedSecret}\n`);
    }
  } finally {
    rl.close();
  }
}

export async function runMenu(db: Database): Promise<void> {
  requireTty();
  for (;;) {
    process.stdout.write("\nClients\n1) List clients\n2) Add client\n3) Remove client\n4) Edit client\n5) Quit\n");
    const rl = createInterface({ input, output });
    let choice: string;
    try {
      choice = (await rl.question("Choice: ")).trim();
    } finally {
      rl.close();
    }
    if (choice === "1") await listedOrEmpty(db);
    else if (choice === "2") await runAddFlow(db);
    else if (choice === "3") await runRemoveFlow(db);
    else if (choice === "4") await runEditFlow(db);
    else if (choice === "5" || /^q(uit)?$/i.test(choice)) return;
    else process.stdout.write("Enter 1-5.\n");
  }
}

if (/clients\.(ts|js)$/.test(process.argv[1] ?? "")) {
  const { db, pool } = requireDatabase();
  try {
    await runMenu(db);
  } finally {
    await pool.end();
  }
}
