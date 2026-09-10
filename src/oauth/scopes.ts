import { DelegatedPermissionSet, type Permission } from "@basis/schema/permissions";

export function scopeGrants(granted: string, required: string): boolean {
  if (granted === required) return true;
  if (!granted.includes(".") || !required.includes(".")) return false;
  return new DelegatedPermissionSet([granted]).has(required as Permission);
}

function getMissingScopes(clientScopes: string[], requiredScopes: string[]) {
  const clientSet = new Set(clientScopes || []);
  return requiredScopes.filter(scope => !clientSet.has(scope));
}

export function scopesCover(granted: Iterable<string>, required: Iterable<string>): boolean {
  const grantedScopes = [...granted];

  console.log(getMissingScopes(grantedScopes, [...required]));

  return [...required].every((requiredScope) =>
    grantedScopes.some((grantedScope) => scopeGrants(grantedScope, requiredScope)),
  );
}
