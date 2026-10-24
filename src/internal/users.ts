import { and, count, desc, eq, inArray, isNull, notInArray, sql } from "drizzle-orm";
import type { Database } from "../database/client.js";
import type { EmailDomainService } from "../database/emailDomains.js";
import {
  authSessions,
  oidcClients,
  oidcPermissions,
  refreshTokens,
  userApplications,
  userPermissions,
  users,
} from "../database/schema.js";
import { deriveBasisStudentDetails } from "../identity.js";
import { compactPermissionClauses } from "../permissions.js";

const allowedFields = new Set(["displayName", "email", "disabled", "picture"]);
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const contentTypePattern = /^image\/[a-z0-9][a-z0-9.+-]*$/i;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

interface PictureInput {
  data: string;
  contentType: string;
}

interface UserPatch {
  displayName?: string | null;
  email?: string;
  disabled?: boolean;
  picture?: PictureInput | null;
}

interface UserPageInput {
  page: number;
  pageSize: number;
}

interface ManagementApplicationUpdate {
  applicationId: string;
  catalogVersion: number;
  grants: string[];
}

export class InternalUserError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 404 | 409,
    readonly code: string,
  ) {
    super(message);
  }
}

function parseManagementPatch(input: unknown) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new InternalUserError("Body must be a JSON object", 400, "invalid_request");
  }
  const body = input as Record<string, unknown>;
  if (Object.keys(body).some((field) => !allowedFields.has(field) && field !== "applications")) {
    throw new InternalUserError("Body contains an unknown or immutable field", 400, "invalid_request");
  }
  if (!Array.isArray(body.applications)) {
    throw new InternalUserError("applications must be an array", 400, "invalid_request");
  }
  const seen = new Set<string>();
  const applications = body.applications.map((value): ManagementApplicationUpdate => {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new InternalUserError("Each application update must be an object", 400, "invalid_request");
    }
    const item = value as Record<string, unknown>;
    if (
      Object.keys(item).some((field) => !["applicationId", "catalogVersion", "grants"].includes(field)) ||
      typeof item.applicationId !== "string" || !item.applicationId.trim() ||
      !Number.isSafeInteger(item.catalogVersion) || (item.catalogVersion as number) < 1 ||
      !Array.isArray(item.grants) || !item.grants.every((grant) => typeof grant === "string")
    ) {
      throw new InternalUserError("Application updates require applicationId, catalogVersion, and string grants", 400, "invalid_request");
    }
    if (seen.has(item.applicationId)) {
      throw new InternalUserError("Application updates must be unique", 400, "invalid_request");
    }
    seen.add(item.applicationId);
    const grants = item.grants as string[];
    if (new Set(grants.map((grant) => grant.toLocaleLowerCase("en-US"))).size !== grants.length) {
      throw new InternalUserError("Permission grants must be unique", 400, "invalid_request");
    }
    return { applicationId: item.applicationId, catalogVersion: item.catalogVersion as number, grants };
  });
  const profile = Object.fromEntries(Object.entries(body).filter(([key]) => key !== "applications"));
  return { patch: Object.keys(profile).length ? parsePatch(profile) : {}, applications };
}

function parsePatch(input: unknown): UserPatch {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new InternalUserError("Body must be a JSON object", 400, "invalid_request");
  }
  const body = input as Record<string, unknown>;
  const fields = Object.keys(body);
  if (!fields.length) throw new InternalUserError("At least one field is required", 400, "invalid_request");
  if (fields.some((field) => !allowedFields.has(field))) {
    throw new InternalUserError("Body contains an unknown or immutable field", 400, "invalid_request");
  }

  const patch: UserPatch = {};
  if ("displayName" in body) {
    if (body.displayName !== null && (typeof body.displayName !== "string" || body.displayName.length > 200)) {
      throw new InternalUserError(
        "displayName must be null or a string of at most 200 characters",
        400,
        "invalid_request",
      );
    }
    patch.displayName = body.displayName as string | null;
  }
  if ("email" in body) {
    if (typeof body.email !== "string" || !emailPattern.test(body.email) || body.email.length > 320) {
      throw new InternalUserError("email must be a valid email address", 400, "invalid_request");
    }
    patch.email = body.email.trim().toLowerCase();
  }
  if ("disabled" in body) {
    if (typeof body.disabled !== "boolean") {
      throw new InternalUserError("disabled must be a boolean", 400, "invalid_request");
    }
    patch.disabled = body.disabled;
  }
  if ("picture" in body) {
    if (body.picture === null) patch.picture = null;
    else {
      if (!body.picture || typeof body.picture !== "object" || Array.isArray(body.picture)) {
        throw new InternalUserError("picture must be null or an object", 400, "invalid_request");
      }
      const picture = body.picture as Record<string, unknown>;
      if (
        Object.keys(picture).some((field) => field !== "data" && field !== "contentType") ||
        typeof picture.data !== "string" ||
        typeof picture.contentType !== "string" ||
        !contentTypePattern.test(picture.contentType)
      ) {
        throw new InternalUserError(
          "picture requires base64 data and an image contentType",
          400,
          "invalid_request",
        );
      }
      const bytes = Buffer.from(picture.data, "base64");
      if (!picture.data || bytes.length > 5 * 1024 * 1024 || bytes.toString("base64") !== picture.data.replace(/\s/g, "")) {
        throw new InternalUserError(
          "picture data must be valid base64 no larger than 5 MB",
          400,
          "invalid_request",
        );
      }
      patch.picture = { data: picture.data, contentType: picture.contentType };
    }
  }
  return patch;
}

function validateUserId(userId: string) {
  if (!uuidPattern.test(userId)) throw new InternalUserError("User ID is invalid", 400, "invalid_request");
}

function parsePagination(input: { page?: string; pageSize?: string }): UserPageInput {
  const page = input.page === undefined ? 1 : Number(input.page);
  const pageSize = input.pageSize === undefined ? 20 : Number(input.pageSize);
  if (!Number.isSafeInteger(page) || page < 1) {
    throw new InternalUserError("page must be a positive integer", 400, "invalid_request");
  }
  if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 100) {
    throw new InternalUserError("pageSize must be an integer between 1 and 100", 400, "invalid_request");
  }
  return { page, pageSize };
}

export function createInternalUserService(db: Database, emailDomains: EmailDomainService) {
  async function listUsers(input: UserPageInput) {
    const offset = (input.page - 1) * input.pageSize;
    const [pageUsers, [summary]] = await Promise.all([
      db
        .select({
          id: users.id,
          displayName: users.displayName,
          email: users.email,
          hasPicture: sql<boolean>`${users.picture} is not null and ${users.pictureContentType} is not null`,
        })
        .from(users)
        .orderBy(desc(users.createdAt), desc(users.id))
        .limit(input.pageSize)
        .offset(offset),
      db.select({ total: count() }).from(users),
    ]);
    const total = summary?.total ?? 0;
    return {
      users: pageUsers,
      pagination: {
        page: input.page,
        pageSize: input.pageSize,
        total,
        totalPages: Math.ceil(total / input.pageSize),
      },
    };
  }

  async function findUser(userId: string) {
    validateUserId(userId);
    const [user] = await db
      .select({
        id: users.id,
        provider: users.provider,
        upstreamIssuer: users.upstreamIssuer,
        upstreamSubject: users.upstreamSubject,
        email: users.email,
        emailSuffixId: users.emailSuffixId,
        studentId: users.studentId,
        schoolDistrict: users.schoolDistrict,
        disabled: users.disabled,
        displayName: users.displayName,
        tokensValidAfter: users.tokensValidAfter,
        createdAt: users.createdAt,
        updatedAt: users.updatedAt,
        hasPicture: sql<boolean>`${users.picture} is not null and ${users.pictureContentType} is not null`,
      })
      .from(users)
      .where(eq(users.id, userId))
      .limit(1);
    return user;
  }

  async function findPicture(userId: string) {
    validateUserId(userId);
    const [picture] = await db
      .select({ data: users.picture, contentType: users.pictureContentType })
      .from(users)
      .where(eq(users.id, userId))
      .limit(1);
    return picture;
  }

  async function patchUser(userId: string, input: unknown) {
    validateUserId(userId);
    const patch = parsePatch(input);
    const values: Partial<typeof users.$inferInsert> = { updatedAt: new Date() };
    if (patch.displayName !== undefined) values.displayName = patch.displayName;
    if (patch.email !== undefined) {
      values.email = patch.email;
      values.emailSuffixId = (await emailDomains.resolveEmail(patch.email))?.suffixId ?? null;
      const { studentId, schoolDistrict } = deriveBasisStudentDetails(patch.email);
      values.studentId = studentId;
      values.schoolDistrict = schoolDistrict;
    }
    if (patch.disabled !== undefined) values.disabled = patch.disabled;
    if (patch.picture !== undefined) {
      values.picture = patch.picture ? Buffer.from(patch.picture.data, "base64") : null;
      values.pictureContentType = patch.picture?.contentType ?? null;
    }

    const disabledAt = patch.disabled === true ? new Date() : undefined;
    if (disabledAt) values.tokensValidAfter = disabledAt;
    let found = false;
    await db.transaction(async (transaction) => {
      const updated = await transaction
        .update(users)
        .set(values)
        .where(eq(users.id, userId))
        .returning({ id: users.id });
      found = updated.length > 0;
      if (!found || !disabledAt) return;
      await transaction.delete(authSessions).where(eq(authSessions.userId, userId));
      await transaction
        .update(refreshTokens)
        .set({ revokedAt: disabledAt })
        .where(and(eq(refreshTokens.userId, userId), isNull(refreshTokens.revokedAt)));
    });
    if (!found) throw new InternalUserError("User not found", 404, "user_not_found");
    return (await findUser(userId))!;
  }

  async function findManagementUser(userId: string) {
    const user = await findUser(userId);
    if (!user) return undefined;
    const affiliated = await db
      .select({
        applicationId: oidcClients.clientId,
        name: sql<string>`${oidcClients.metadata}->>'name'`,
        catalogVersion: oidcClients.permissionCatalogVersion,
      })
      .from(userApplications)
      .innerJoin(oidcClients, eq(userApplications.applicationId, oidcClients.clientId))
      .where(eq(userApplications.userId, userId));
    const applicationIds = affiliated.map((application) => application.applicationId);
    const [definitions, grants] = applicationIds.length
      ? await Promise.all([
          db.select({
            applicationId: oidcPermissions.clientId,
            permission: oidcPermissions.permission,
            description: oidcPermissions.description,
          }).from(oidcPermissions).where(inArray(oidcPermissions.clientId, applicationIds)),
          db.select({
            applicationId: userPermissions.applicationId,
            permission: userPermissions.permission,
          }).from(userPermissions).where(and(
            eq(userPermissions.userId, userId),
            inArray(userPermissions.applicationId, applicationIds),
          )),
        ])
      : [[], []] as [never[], never[]];
    const applications = affiliated.map((application) => ({
      applicationId: application.applicationId,
      name: application.name || application.applicationId,
      catalogVersion: application.catalogVersion,
      permissions: definitions
        .filter((definition) => definition.applicationId === application.applicationId)
        .map(({ permission, description }) => ({ permission, description }))
        .sort((left, right) => left.permission.localeCompare(right.permission)),
      grants: grants
        .filter((grant) => grant.applicationId === application.applicationId)
        .map(({ permission }) => permission)
        .sort(),
    }));
    return { user: { ...user, applications } };
  }

  async function patchManagementUser(userId: string, input: unknown) {
    validateUserId(userId);
    const { patch, applications } = parseManagementPatch(input);
    const values: Partial<typeof users.$inferInsert> = { updatedAt: new Date() };
    if (patch.displayName !== undefined) values.displayName = patch.displayName;
    if (patch.email !== undefined) {
      values.email = patch.email;
      values.emailSuffixId = (await emailDomains.resolveEmail(patch.email))?.suffixId ?? null;
      const { studentId, schoolDistrict } = deriveBasisStudentDetails(patch.email);
      values.studentId = studentId;
      values.schoolDistrict = schoolDistrict;
    }
    if (patch.disabled !== undefined) values.disabled = patch.disabled;
    if (patch.picture !== undefined) {
      values.picture = patch.picture ? Buffer.from(patch.picture.data, "base64") : null;
      values.pictureContentType = patch.picture?.contentType ?? null;
    }
    const disabledAt = patch.disabled === true ? new Date() : undefined;
    if (disabledAt) values.tokensValidAfter = disabledAt;

    await db.transaction(async (tx) => {
      const updated = await tx.update(users).set(values).where(eq(users.id, userId)).returning({ id: users.id });
      if (!updated.length) throw new InternalUserError("User not found", 404, "user_not_found");
      if (disabledAt) {
        await tx.delete(authSessions).where(eq(authSessions.userId, userId));
        await tx.update(refreshTokens).set({ revokedAt: disabledAt })
          .where(and(eq(refreshTokens.userId, userId), isNull(refreshTokens.revokedAt)));
      }

      for (const update of applications) {
        const [affiliation] = await tx
          .select({ catalogVersion: oidcClients.permissionCatalogVersion })
          .from(userApplications)
          .innerJoin(oidcClients, eq(userApplications.applicationId, oidcClients.clientId))
          .where(and(
            eq(userApplications.userId, userId),
            eq(userApplications.applicationId, update.applicationId),
          ))
          .for("update")
          .limit(1);
        if (!affiliation) {
          throw new InternalUserError("Application is not affiliated with this user", 400, "invalid_application");
        }
        if (affiliation.catalogVersion !== update.catalogVersion) {
          throw new InternalUserError("The application permissions changed; reload before saving", 409, "stale_permissions");
        }
        const definitions = await tx
          .select({ permission: oidcPermissions.permission, description: oidcPermissions.description })
          .from(oidcPermissions)
          .where(eq(oidcPermissions.clientId, update.applicationId));
        let clauses: string[];
        try {
          clauses = compactPermissionClauses(update.grants, definitions);
        } catch (error) {
          throw new InternalUserError(
            error instanceof Error ? error.message : "Permission grant is invalid",
            400,
            "invalid_permission",
          );
        }
        await tx.delete(userPermissions).where(and(
          eq(userPermissions.userId, userId),
          eq(userPermissions.applicationId, update.applicationId),
        ));
        if (clauses.length) {
          await tx.insert(userPermissions).values(clauses.map((permission) => ({
            userId,
            applicationId: update.applicationId,
            permission,
          })));
        }
      }
    });
    return (await findManagementUser(userId))!;
  }

  return { listUsers, findUser, findPicture, patchUser, findManagementUser, patchManagementUser };
}

export type InternalUserService = ReturnType<typeof createInternalUserService>;
export const internalUserInternals = { parsePagination, parsePatch, parseManagementPatch, validateUserId };
