import { eq } from "drizzle-orm";
import type { Database } from "./client.js";
import { acceptedEmailDomains, emailDomainSuffixes } from "./schema.js";
import { loginTypeFor, type LoginType } from "../loginTypes.js";

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const suffixPattern = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export class EmailDomainError extends Error {
  constructor(message: string, readonly code: "invalid_input" | "not_found") {
    super(message);
  }
}

export function normalizeEmailSuffix(value: string): string {
  const suffix = value.trim().toLowerCase();
  if (suffix.startsWith("@") || suffix.length > 253 || !suffixPattern.test(suffix)) {
    throw new EmailDomainError("Email suffix must be a valid domain without @", "invalid_input");
  }
  return suffix;
}

function validateUuid(value: string, name: string): string {
  if (!uuidPattern.test(value)) throw new EmailDomainError(`${name} must be a UUID`, "invalid_input");
  return value.toLowerCase();
}

export function emailSuffix(email: string): string | undefined {
  return email.trim().toLowerCase().match(/^[^@\s]+@([^@\s]+)$/)?.[1];
}

export function createEmailDomainService(db: Database) {
  async function listPolicies() {
    return db.select().from(acceptedEmailDomains);
  }

  async function getPolicy(id: string) {
    validateUuid(id, "Policy ID");
    const [policy] = await db.select().from(acceptedEmailDomains).where(eq(acceptedEmailDomains.id, id)).limit(1);
    return policy;
  }

  async function createPolicy(input: { organizationId: string; firstParty: boolean }) {
    const [policy] = await db.insert(acceptedEmailDomains).values({
      id: crypto.randomUUID(),
      organizationId: validateUuid(input.organizationId, "Organization ID"),
      firstParty: input.firstParty,
    }).returning();
    return policy!;
  }

  async function updatePolicy(id: string, input: { organizationId?: string; firstParty?: boolean }) {
    validateUuid(id, "Policy ID");
    if (input.organizationId === undefined && input.firstParty === undefined) {
      throw new EmailDomainError("At least one policy field is required", "invalid_input");
    }
    const [policy] = await db.update(acceptedEmailDomains).set({
      ...(input.organizationId === undefined ? {} : { organizationId: validateUuid(input.organizationId, "Organization ID") }),
      ...(input.firstParty === undefined ? {} : { firstParty: input.firstParty }),
      updatedAt: new Date(),
    }).where(eq(acceptedEmailDomains.id, id)).returning();
    if (!policy) throw new EmailDomainError("Accepted email domain policy not found", "not_found");
    return policy;
  }

  async function deletePolicy(id: string) {
    validateUuid(id, "Policy ID");
    const [policy] = await db.delete(acceptedEmailDomains).where(eq(acceptedEmailDomains.id, id)).returning();
    if (!policy) throw new EmailDomainError("Accepted email domain policy not found", "not_found");
    return policy;
  }

  async function listSuffixes() {
    return db.select().from(emailDomainSuffixes);
  }

  async function getSuffix(id: string) {
    validateUuid(id, "Suffix ID");
    const [suffix] = await db.select().from(emailDomainSuffixes).where(eq(emailDomainSuffixes.id, id)).limit(1);
    return suffix;
  }

  async function createSuffix(input: { suffix: string; acceptedEmailDomainId: string }) {
    const [suffix] = await db.insert(emailDomainSuffixes).values({
      id: crypto.randomUUID(),
      suffix: normalizeEmailSuffix(input.suffix),
      acceptedEmailDomainId: validateUuid(input.acceptedEmailDomainId, "Accepted email domain ID"),
    }).returning();
    return suffix!;
  }

  async function updateSuffix(id: string, input: { suffix?: string; acceptedEmailDomainId?: string }) {
    validateUuid(id, "Suffix ID");
    if (input.suffix === undefined && input.acceptedEmailDomainId === undefined) {
      throw new EmailDomainError("At least one suffix field is required", "invalid_input");
    }
    const [suffix] = await db.update(emailDomainSuffixes).set({
      ...(input.suffix === undefined ? {} : { suffix: normalizeEmailSuffix(input.suffix) }),
      ...(input.acceptedEmailDomainId === undefined ? {} : {
        acceptedEmailDomainId: validateUuid(input.acceptedEmailDomainId, "Accepted email domain ID"),
      }),
      updatedAt: new Date(),
    }).where(eq(emailDomainSuffixes.id, id)).returning();
    if (!suffix) throw new EmailDomainError("Email domain suffix not found", "not_found");
    return suffix;
  }

  async function deleteSuffix(id: string) {
    validateUuid(id, "Suffix ID");
    const [suffix] = await db.delete(emailDomainSuffixes).where(eq(emailDomainSuffixes.id, id)).returning();
    if (!suffix) throw new EmailDomainError("Email domain suffix not found", "not_found");
    return suffix;
  }

  async function resolveEmail(email: string): Promise<{
    suffixId: string;
    suffix: string;
    organizationId: string;
    firstParty: boolean;
    loginType: LoginType;
  } | undefined> {
    const domain = emailSuffix(email);
    if (!domain) return undefined;
    const [match] = await db.select({
      suffixId: emailDomainSuffixes.id,
      suffix: emailDomainSuffixes.suffix,
      organizationId: acceptedEmailDomains.organizationId,
      firstParty: acceptedEmailDomains.firstParty,
    }).from(emailDomainSuffixes)
      .innerJoin(acceptedEmailDomains, eq(emailDomainSuffixes.acceptedEmailDomainId, acceptedEmailDomains.id))
      .where(eq(emailDomainSuffixes.suffix, domain))
      .limit(1);
    return match ? { ...match, loginType: loginTypeFor(match.firstParty) } : undefined;
  }

  async function firstPartyOrganizationId(): Promise<string> {
    const rows = await db.select({ organizationId: acceptedEmailDomains.organizationId })
      .from(acceptedEmailDomains)
      .where(eq(acceptedEmailDomains.firstParty, true));
    if (rows.length !== 1) throw new Error("Exactly one first-party email domain policy is required");
    return rows[0]!.organizationId;
  }

  return {
    listPolicies, getPolicy, createPolicy, updatePolicy, deletePolicy,
    listSuffixes, getSuffix, createSuffix, updateSuffix, deleteSuffix,
    resolveEmail, firstPartyOrganizationId,
  };
}

export type EmailDomainService = ReturnType<typeof createEmailDomainService>;
