export type PermissionDefinition = { permission: string; description: string };

const keyOf = (value: string) => value.toLocaleLowerCase("en-US");

/** Validate and compact explicit grants without turning exact leaves into wildcards. */
export function compactPermissionClauses(
  input: readonly string[],
  definitions: readonly PermissionDefinition[],
): string[] {
  const canonical = new Map(definitions.map(({ permission }) => [keyOf(permission), permission]));
  const prefixes = new Map<string, string>();
  for (const { permission } of definitions) {
    const parts = permission.split(".");
    for (let length = 1; length < parts.length; length += 1) {
      const prefix = parts.slice(0, length).join(".");
      prefixes.set(keyOf(prefix), prefix);
    }
  }

  const clauses = new Map<string, string>();
  for (const raw of input) {
    const value = raw.trim();
    if (!value || value !== raw) throw new Error("Permission clauses must be non-empty and trimmed");
    const comparison = keyOf(value);
    const exact = canonical.get(comparison);
    if (exact) {
      clauses.set(keyOf(exact), exact);
      continue;
    }
    if (comparison.endsWith(".all")) {
      const prefix = prefixes.get(comparison.slice(0, -4));
      if (!prefix) throw new Error(`Permission wildcard has no defined descendants: ${value}`);
      const wildcard = `${prefix}.all`;
      clauses.set(keyOf(wildcard), wildcard);
      continue;
    }
    throw new Error(`Permission is not defined for this application: ${value}`);
  }

  const sorted = [...clauses.values()].sort((a, b) => a.length - b.length || a.localeCompare(b));
  const compacted: string[] = [];
  for (const clause of sorted) {
    if (compacted.some((parent) => {
      const parentKey = keyOf(parent);
      const clauseKey = keyOf(clause);
      return parentKey.endsWith(".all") && clauseKey.startsWith(`${parentKey.slice(0, -4)}.`);
    })) continue;
    compacted.push(clause);
  }
  return compacted;
}

export function expandPermissionClauses(
  clauses: readonly string[],
  definitions: readonly PermissionDefinition[],
): string[] {
  const normalized = clauses.map(keyOf);
  return definitions
    .map(({ permission }) => permission)
    .filter((permission) => normalized.some((clause) => {
      if (clause === keyOf(permission)) return true;
      return clause.endsWith(".all") && keyOf(permission).startsWith(`${clause.slice(0, -4)}.`);
    }))
    .sort();
}

/** Drop clauses invalidated by a changed catalog, preserving any surviving wildcard. */
export function prunePermissionClauses(
  clauses: readonly string[],
  definitions: readonly PermissionDefinition[],
): string[] {
  const valid = new Set<string>();
  for (const clause of clauses) {
    try {
      for (const normalized of compactPermissionClauses([clause], definitions)) valid.add(normalized);
    } catch {
      // An exact permission may have been deleted, or a wildcard may have no
      // remaining descendants. Both are removed lazily on the next login.
    }
  }
  return compactPermissionClauses([...valid], definitions);
}
