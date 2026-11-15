export const portalScopedPermissions = {
  Applications: ["read", "update", "delete"],
  Resources: ["read", "update", "delete"],
} as const;

export const portalScopedDefinitions = Object.fromEntries(
  Object.entries(portalScopedPermissions).flatMap(([section, actions]) =>
    actions.flatMap((action) =>
      (["me", "others"] as const).map((target) => [
        `BiszPortal.${section}.${action}.${target}`,
        `${action[0]!.toUpperCase()}${action.slice(1)} ${target === "me" ? "own" : "other"} ${section.toLowerCase()}`,
      ]),
    ),
  ),
);

export const portalScopedDefaults = Object.keys(portalScopedDefinitions)
  .filter((permission) => permission.endsWith(".me"));

export const retiredPortalPermissions = new Set([
  "biszportal.applications.read",
  "biszportal.applications.update",
  "biszportal.applications.delete",
  "biszportal.applicationscopes.manage",
]);
