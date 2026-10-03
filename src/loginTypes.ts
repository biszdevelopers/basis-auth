export const loginTypes = ["FIRST_PARTY", "THIRD_PARTY", "COMMON"] as const;

export type LoginType = (typeof loginTypes)[number];

export function loginTypeFor(firstParty: boolean | null | undefined): LoginType {
  if (firstParty === true) return "FIRST_PARTY";
  if (firstParty === false) return "THIRD_PARTY";
  return "COMMON";
}

export function microsoftAuthorityFor(loginTypes: LoginType[], firstPartyOrganizationId: string): string {
  if (loginTypes.includes("COMMON")) return "common";
  if (loginTypes.includes("THIRD_PARTY")) return "organizations";
  return firstPartyOrganizationId;
}
