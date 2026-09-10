import { and, eq, inArray, sql } from "drizzle-orm";
import type { BootstrapPermissionGrant } from "./config.js";
import type { Database } from "./database/client.js";
import { userPermissions, users } from "./database/schema.js";

export interface UpstreamIdentity {
  provider: string;
  issuer: string;
  subject: string;
  email: string;
  emailVerified: boolean;
  displayName?: string;
  picture?: { data: Buffer; contentType: string };
}

export interface BasisStudentDetails {
  studentId: string | null;
  schoolDistrict: string | null;
}

const verifiedEmailDomains = new Set(["basischina.com", "basis-global.com"]);

export function isVerifiedBasisEmail(email: string): boolean {
  const domain = email.trim().toLowerCase().match(/^[^@\s]+@([^@\s]+)$/)?.[1];
  return Boolean(domain && verifiedEmailDomains.has(domain));
}

/**
 * Basis student accounts use `<name><student-id>-<district>@basischina.com`.
 * Teacher and service accounts still expose their district but have no ID.
 */
export function deriveBasisStudentDetails(email: string): BasisStudentDetails {
  const normalizedEmail = email.trim().toLowerCase();
  const localPart = normalizedEmail.match(/^([^@]+)@basischina\.com$/)?.[1];
  if (!localPart) return { studentId: null, schoolDistrict: null };

  const student = localPart.match(/^.+?(\d+)-([a-z0-9]+)$/i);
  if (student) return { studentId: student[1]!, schoolDistrict: student[2]!.toLowerCase() };

  const district = localPart.match(/^.+-([a-z0-9]+)$/i);
  return { studentId: null, schoolDistrict: district ? district[1]!.toLowerCase() : null };
}

export function createIdentityService(
  db: Database,
  defaultPermission: string,
  bootstrapGrants: BootstrapPermissionGrant[],
) {
  async function permissionsFor(userId: string): Promise<string[]> {
    const rows = await db
      .select({ permission: userPermissions.permission })
      .from(userPermissions)
      .where(eq(userPermissions.userId, userId));
    return rows.map((row) => row.permission).sort();
  }

  async function upsertFromMicrosoft(identity: UpstreamIdentity) {
    const normalizedEmail = identity.email.trim().toLowerCase();
    const { studentId, schoolDistrict } = deriveBasisStudentDetails(normalizedEmail);
    const [existing] = await db
      .select()
      .from(users)
      .where(
        and(
          eq(users.provider, identity.provider),
          eq(users.upstreamIssuer, identity.issuer),
          eq(users.upstreamSubject, identity.subject),
        ),
      )
      .limit(1);

    const id = existing?.id ?? crypto.randomUUID();
    const [user] = await db
      .insert(users)
      .values({
        id,
        provider: identity.provider,
        upstreamIssuer: identity.issuer,
        upstreamSubject: identity.subject,
        email: normalizedEmail,
        emailVerified: identity.emailVerified,
        studentId,
        schoolDistrict,
        displayName: identity.displayName,
        picture: identity.picture?.data,
        pictureContentType: identity.picture?.contentType,
      })
      .onConflictDoUpdate({
        target: [users.provider, users.upstreamIssuer, users.upstreamSubject],
        set: {
          provider: identity.provider,
          email: normalizedEmail,
          emailVerified: identity.emailVerified,
          studentId,
          schoolDistrict,
          displayName: identity.displayName,
          picture: identity.picture?.data,
          pictureContentType: identity.picture?.contentType,
          updatedAt: new Date(),
        },
      })
      .returning();

    const bootstrap = bootstrapGrants.find((grant) => grant.email === normalizedEmail);
    const permissions = new Set([defaultPermission, ...(bootstrap?.permissions ?? [])]);
    await db
      .insert(userPermissions)
      .values([...permissions].map((permission) => ({ userId: user!.id, permission })))
      .onConflictDoNothing();
    return user!;
  }

  async function findAccount(userId: string) {
    const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    if (!user || user.disabled) return undefined;
    return {
      accountId: user.id,
      async claims(_use: string, scope: string) {
        const scopes = new Set(scope.split(" "));
        return {
          sub: user.id,
          ...(scopes.has("profile")
            ? {
                name: user.displayName,
                picture:
                  user.picture && user.pictureContentType
                    ? `data:${user.pictureContentType};base64,${user.picture.toString("base64")}`
                    : undefined,
              }
            : {}),
          ...(scopes.has("email")
            ? { email: user.email, email_verified: user.emailVerified }
            : {}),
        };
      },
    };
  }

  async function findUsersByIds(ids: string[]) {
    return ids.length ? db.select().from(users).where(inArray(users.id, ids)) : [];
  }

  async function findUser(userId: string) {
    const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    return user;
  }

  const findUserCompactStmt = db
    .select({
      id: users.id,
      disabled: users.disabled,
      tokensValidAfter: users.tokensValidAfter,
    })
    .from(users)
    .where(eq(users.id, sql.placeholder("id")))
    .limit(1)
    .prepare("find_user_compact");

  async function findUserCompact(userId: string) {
    const [user] = await findUserCompactStmt.execute({ id: userId });
    return user;
  }

  return { upsertFromMicrosoft, findAccount, permissionsFor, findUsersByIds, findUser, findUserCompact };
}

export type IdentityService = ReturnType<typeof createIdentityService>;
