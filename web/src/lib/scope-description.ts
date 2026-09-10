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
  permissions: { description: "Access your Basis permissions", sensitive: true },
  "Profile.all": {
    description: "View and update all Network Hackathon profile data",
    sensitive: true,
  },
  "Projects.read.all": {
    description: "View all Network Hackathon projects, including your own and others' projects",
    sensitive: false,
  },
  "Projects.write.self": {
    description: "Create and update your own Network Hackathon project",
    sensitive: true,
  },
  "Teams.all": {
    description: "View and manage all Network Hackathon team and membership operations",
    sensitive: true,
  },
  "Voting.all": {
    description: "View and perform all Network Hackathon voting operations for your account",
    sensitive: true,
  },
  "Judging.all": {
    description: "View and perform all judging operations for assigned Network Hackathon projects",
    sensitive: true,
  },
  "Seasons.all": {
    description: "Perform all Network Hackathon season and event-setting operations",
    sensitive: true,
  },
  "Files.all": {
    description: "View and manage all Network Hackathon debug files",
    sensitive: true,
  },
  "Chatbot.use": {
    description: "Use the Network Hackathon chatbot",
    sensitive: false,
  },
  "Database.export": {
    description: "Export Network Hackathon data",
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
