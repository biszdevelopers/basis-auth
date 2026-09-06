import "dotenv/config";
import { randomBytes } from "node:crypto";
import { stdin as input, stdout as output } from "node:process";
import { createInterface, type Interface } from "node:readline/promises";
import { eq } from "drizzle-orm";
import { clientInputSchema, type ClientSeed } from "../src/config.js";
import { createDatabase, type Database } from "../src/database/client.js";
import { seedConfiguration, type StoredClientMetadata } from "../src/database/seed.js";
import { oidcClients, resourceServers } from "../src/database/schema.js";

// ponytail: stdlib readline TUI; no prompt dependency.

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

function printClients(clients: ListedClient[]): void {
  if (!clients.length) {
    process.stdout.write("No clients registered.\n");
    return;
  }
  clients.forEach((client, index) => {
    process.stdout.write(`${index + 1}) ${client.name} (${client.clientId})${client.public ? " [public]" : ""}\n`);
    if (client.redirectUris.length) process.stdout.write(`   redirects: ${client.redirectUris.join(", ")}\n`);
  });
}

export interface NewClient {
  input: Omit<ClientSeed, "clientId">;
  generatedSecret: string | null;
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

  let redirectUris: string[] = [];
  while (!redirectUris.length) {
    const candidates = splitList(await ask(rl, "Redirect URIs (comma-separated)"));
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
    else redirectUris = candidates;
  }

  if (audiences.length) {
    process.stdout.write("Registered resources:\n");
    audiences.forEach((audience, index) => process.stdout.write(`  ${index + 1}) ${audience}\n`));
  }
  let resources: string[] = [];
  while (!resources.length) {
    resources = splitList(await ask(rl, "Resources (comma-separated numbers or values)")).map((entry) => {
      const byNumber = /^\d+$/.test(entry) ? audiences[Number(entry) - 1] : undefined;
      return byNumber ?? entry;
    });
    if (!resources.length) process.stdout.write("At least one resource is required.\n");
  }

  const scopes = splitList(await ask(rl, "Scopes (comma-separated)", "openid, profile, email"));
  const requireConsent = await askYesNo(rl, "Show consent screen?", true);

  let filterMode: "whitelist" | "blacklist" | null = null;
  for (;;) {
    const raw = (await ask(rl, "Account filter (blank, whitelist, blacklist)")).toLowerCase();
    if (!raw) break;
    if (raw === "whitelist" || raw === "blacklist") {
      filterMode = raw;
      break;
    }
    process.stdout.write('Enter blank, "whitelist", or "blacklist".\n');
  }
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

  process.stdout.write(
    `\nName: ${input.name ?? "(none)"}\nType: ${input.public ? "public" : "confidential"}\n` +
      `Redirects: ${input.redirectUris.join(", ")}\nResources: ${input.resources.join(", ")}\n` +
      `Scopes: ${input.scopes.join(", ")}\nConsent: ${input.requireConsent ? "shown" : "skipped"}\n` +
      `Filter: ${input.filterMode ?? "none"}${input.filterContent.length ? ` (${input.filterContent.join(", ")})` : ""}\n`,
  );
  if (!(await askYesNo(rl, "Create this client?", true))) return null;
  return { input, generatedSecret };
}

export async function runAddFlow(db: Database): Promise<void> {
  requireTty();
  const resources = await db.select().from(resourceServers);
  const rl = createInterface({ input, output });
  try {
    const created = await promptNewClient(
      rl,
      resources.map((resource) => resource.audience).sort(),
    );
    if (!created) {
      process.stdout.write("Cancelled.\n");
      return;
    }
    const client: ClientSeed = { ...created.input, clientId: crypto.randomUUID() };
    await seedConfiguration(db, [client], []);
    process.stdout.write(`Created client ${client.clientId}\n`);
    if (created.generatedSecret) {
      process.stdout.write(`Client secret (copy now, only a hash is stored): ${created.generatedSecret}\n`);
    }
  } finally {
    rl.close();
  }
}

export async function runRemoveFlow(db: Database, preselected?: string): Promise<void> {
  if (preselected) {
    process.stdout.write(`${await deleteClientById(db, preselected)}\n`);
    return;
  }
  requireTty();
  const clients = await listClients(db);
  if (!clients.length) {
    process.stdout.write("No clients registered.\n");
    return;
  }
  printClients(clients);
  const rl = createInterface({ input, output });
  try {
    const raw = await ask(rl, "Client to remove (number or id)");
    const byNumber = /^\d+$/.test(raw) ? clients[Number(raw) - 1] : undefined;
    const selected = byNumber ?? clients.find((client) => client.clientId === raw);
    if (!selected) throw new Error(`No client matches "${raw}"`);
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

export async function runMenu(db: Database): Promise<void> {
  requireTty();
  for (;;) {
    process.stdout.write("\nClients\n1) List clients\n2) Add client\n3) Remove client\n4) Quit\n");
    const rl = createInterface({ input, output });
    let choice: string;
    try {
      choice = (await rl.question("Choice: ")).trim();
    } finally {
      rl.close();
    }
    if (choice === "1") printClients(await listClients(db));
    else if (choice === "2") await runAddFlow(db);
    else if (choice === "3") await runRemoveFlow(db);
    else if (choice === "4" || /^q(uit)?$/i.test(choice)) return;
    else process.stdout.write("Enter 1-4.\n");
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
