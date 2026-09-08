import { APIError as SchemaAPIError } from "@basis/schema/api";

export class APIError extends SchemaAPIError {}

export class OAuthError extends APIError {}
