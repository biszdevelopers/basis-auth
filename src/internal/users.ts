import { and, eq, isNull, sql } from "drizzle-orm";
import type { Database } from "../database/client.js";
import { authSessions, refreshTokens, users } from "../database/schema.js";
import { deriveBasisStudentDetails, isVerifiedBasisEmail } from "../identity.js";

const allowedFields = new Set(["displayName", "email", "emailVerified", "disabled", "picture"]);
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
  emailVerified?: boolean;
  disabled?: boolean;
  picture?: PictureInput | null;
}

export class InternalUserError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 404,
    readonly code: "invalid_request" | "user_not_found",
  ) {
    super(message);
  }
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
  if ("emailVerified" in body) {
    if (typeof body.emailVerified !== "boolean") {
      throw new InternalUserError("emailVerified must be a boolean", 400, "invalid_request");
    }
    patch.emailVerified = body.emailVerified;
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

export function createInternalUserService(db: Database) {
  async function findUser(userId: string) {
    validateUserId(userId);
    const [user] = await db
      .select({
        id: users.id,
        provider: users.provider,
        email: users.email,
        emailVerified: users.emailVerified,
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
      const { studentId, schoolDistrict } = deriveBasisStudentDetails(patch.email);
      values.studentId = studentId;
      values.schoolDistrict = schoolDistrict;
      values.emailVerified = isVerifiedBasisEmail(patch.email);
    }
    if (patch.emailVerified !== undefined && patch.email === undefined) values.emailVerified = patch.emailVerified;
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

  return { findUser, findPicture, patchUser };
}

export type InternalUserService = ReturnType<typeof createInternalUserService>;
export const internalUserInternals = { parsePatch, validateUserId };
