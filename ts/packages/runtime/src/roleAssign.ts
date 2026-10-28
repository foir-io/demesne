import { DriverValues, run } from "./engine.js";
import type { RoleAssignmentSurface, ParamStatement, SqlArg } from "./types.js";

function assign(
  op: string,
  surface: RoleAssignmentSurface,
  assignmentID: string,
  subjectID: string,
  roleID: string,
  scope: readonly string[],
  grantedBy: string,
  extra: Record<string, SqlArg>,
): ParamStatement {
  const values = new DriverValues();
  return values.statement(op, { surface, assignmentID, subjectID, roleID, scope, grantedBy, extra: values.holdAll(extra) });
}

export function assignInsert(
  p: RoleAssignmentSurface,
  assignmentID: string,
  subjectID: string,
  roleID: string,
  scope: readonly string[],
  grantedBy: string,
  extra: Record<string, SqlArg> = {},
): ParamStatement {
  return assign("roleAssignment.assignInsert", p, assignmentID, subjectID, roleID, scope, grantedBy, extra);
}

export function assignTouchInsert(
  p: RoleAssignmentSurface,
  assignmentID: string,
  subjectID: string,
  roleID: string,
  scope: readonly string[],
  grantedBy: string,
  extra: Record<string, SqlArg> = {},
): ParamStatement {
  return assign("roleAssignment.assignTouchInsert", p, assignmentID, subjectID, roleID, scope, grantedBy, extra);
}

export function revokeSQL(p: RoleAssignmentSurface): string {
  return run("roleAssignment.revokeSQL", { surface: p });
}

export function listForRoleSQL(p: RoleAssignmentSurface): string {
  return run("roleAssignment.listForRoleSQL", { surface: p });
}

export function listForPrincipalSQL(p: RoleAssignmentSurface): string {
  return run("roleAssignment.listForPrincipalSQL", { surface: p });
}
