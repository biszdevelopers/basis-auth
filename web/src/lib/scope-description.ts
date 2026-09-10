export interface ScopeDescription {
  scope: string;
  description: string;
  sensitive: boolean;
}

const knownScopes: Record<string, Omit<ScopeDescription, "scope">> = {
  openid: { description: "Verify your identity", sensitive: false },
  profile: { description: "Access your name and profile picture", sensitive: false },
  email: { description: "Access your email address", sensitive: false },
  offline_access: {
    description: "Maintain access while offline",
    sensitive: true,
  },
};

function words(value: string) {
  return value.replace(/[._:-]+/g, " ");
}

export function describeScope(scope: string) {
  const known = knownScopes[scope];
  if (known) return { scope, ...known };

  const [resource, action] = scope.split(".");
  if (action === "access") {
    return { scope, description: `Access ${words(resource)}`, sensitive: false };
  }
  if (resource && action === "read") {
    return { scope, description: `View your ${words(resource)}`, sensitive: false };
  }
  if (resource && action === "write") {
    return { scope, description: `View and modify your ${words(resource)}`, sensitive: true };
  }
  return { scope, description: `Access your ${words(scope)}`, sensitive: false };
}

export function describeScopes(scopes: string[]) {
  return scopes
    .map(describeScope)
    .sort((left, right) => Number(right.sensitive) - Number(left.sensitive));
}
