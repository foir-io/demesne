/**
 * The PDP decision tri-state, mirroring demesne's Go `Decision` (runtime.go).
 *
 * Modeled as a string union whose values ARE the canonical strings Go's
 * `Decision.String()` returns (`allow` / `deny` / `ungoverned`), so there is no number
 * ↔ string ambiguity and the value is its own display form. The named constants on
 * {@link Decision} give call sites the same `Decision.Allow` fidelity as the Go API.
 *
 *   - Allow:        the procedure is governed and the caller holds the required permission.
 *   - Deny:         the procedure is governed and the caller lacks the required permission.
 *   - NotGoverned:  this PDP makes no claim on the procedure (explicitly exempt, or absent);
 *                   the caller decides what that means — other layers may still apply.
 */
export const Decision = {
  Allow: "allow",
  Deny: "deny",
  NotGoverned: "ungoverned",
} as const;

export type Decision = (typeof Decision)[keyof typeof Decision];

/**
 * The canonical string form of a decision — Go's `Decision.String()`. Since a Decision
 * already IS its string, this is the identity, provided for API symmetry with the Go side.
 */
export function decisionString(d: Decision): string {
  return d;
}
