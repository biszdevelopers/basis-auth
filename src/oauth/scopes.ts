import { DelegatedPermissionSet, type Permission } from "@basis/schema/permissions";

export function scopeGrants(granted: string, required: string): boolean {
  if (granted === required) return true;
  if (!granted.includes(".") || !required.includes(".")) return false;
  return new DelegatedPermissionSet([granted]).has(required as Permission);
}

export function scopesCover(granted: Iterable<string>, required: Iterable<string>): boolean {
  const grantedScopes = [...granted];
  return [...required].every((requiredScope) =>
    grantedScopes.some((grantedScope) => scopeGrants(grantedScope, requiredScope)),
  );
}
