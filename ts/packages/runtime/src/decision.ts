
export const Decision = {
  Allow: "allow",
  Deny: "deny",
  NotGoverned: "ungoverned",
} as const;

export type Decision = (typeof Decision)[keyof typeof Decision];

export function decisionString(d: Decision): string {
  return d;
}
