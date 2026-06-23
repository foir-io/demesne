import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  claimsSetSQL,
  setRoleSQL,
  sessionSetupSQL,
  mintClaimsValuesWithExtra,
  checkSQL,
  checkManySQL,
  listResourcesSQL,
  checkEditSQL,
  listResourcesFastSQL,
  assignmentsSQL,
  roleAssignments,
  levelGrants,
  resourceAccess,
} from "../src/index.js";

interface OracleCase {
  kind: string;
  input?: Record<string, unknown>;
  expect: unknown;
}
interface SpecEntry {
  projections: Record<string, unknown>;
  cases: OracleCase[];
}

const oracle = JSON.parse(
  readFileSync(fileURLToPath(new URL("./generated/oracle.json", import.meta.url)), "utf8"),
) as Record<string, SpecEntry>;

function appObj(proj: any, name: unknown): any {

  return proj.appSurface.find((o: any) => o.object === name);
}

function runCase(proj: any, c: OracleCase): unknown {
  const i: any = c.input ?? {};
  switch (c.kind) {
    case "claims.claimsSetSQL":
      return claimsSetSQL(proj.claims, i.local);
    case "claims.setRoleSQL":
      return setRoleSQL(proj.claims, i.local);
    case "claims.sessionSetupSQL":
      return sessionSetupSQL(proj.claims, i.local);
    case "claims.mintWithExtra":
      return mintClaimsValuesWithExtra(proj.claims.contract, i.values, i.extra);

    case "appSurface.checkSQL":
      return checkSQL(appObj(proj, i.object));
    case "appSurface.checkManySQL":
      return checkManySQL(appObj(proj, i.object));
    case "appSurface.listResourcesSQL":
      return listResourcesSQL(appObj(proj, i.object));
    case "appSurface.checkEditSQL":
      return checkEditSQL(appObj(proj, i.object));
    case "appSurface.listResourcesFastSQL":
      return listResourcesFastSQL(appObj(proj, i.object));

    case "holds.assignmentsSQL":
      return assignmentsSQL(proj.holdsResolver);

    case "roleAssignment.revokeSQL":
      return roleAssignments.revokeSQL(proj.roleAssignment);
    case "roleAssignment.listForRoleSQL":
      return roleAssignments.listForRoleSQL(proj.roleAssignment);
    case "roleAssignment.listForPrincipalSQL":
      return roleAssignments.listForPrincipalSQL(proj.roleAssignment);
    case "roleAssignment.assignInsert":
      return roleAssignments.assignInsert(proj.roleAssignment, i.assignmentID, i.subjectID, i.roleID, i.scope, i.grantedBy, i.extra);
    case "roleAssignment.assignTouchInsert":
      return roleAssignments.assignTouchInsert(proj.roleAssignment, i.assignmentID, i.subjectID, i.roleID, i.scope, i.grantedBy, i.extra);

    case "levelGrant.revokeSQL":
      return levelGrants.revokeSQL(proj.grants[i.grant]);
    case "levelGrant.listSQL":
      return levelGrants.listSQL(proj.grants[i.grant]);
    case "levelGrant.grantInsert":
      return levelGrants.grantInsert(proj.grants[i.grant], i.grantID, i.granteeID, i.levelID, i.grantedBy, i.expiresAt, i.extra);

    case "resourceAccess.modeSQL":
      return resourceAccess.modeSQL(proj.resourceAccess[i.object]);
    case "resourceAccess.setVisibilitySQL":
      return resourceAccess.setVisibilitySQL(proj.resourceAccess[i.object]);
    case "resourceAccess.listGrantsSQL":
      return resourceAccess.listGrantsSQL(proj.resourceAccess[i.object]);
    case "resourceAccess.accessorsSQL":
      return resourceAccess.accessorsSQL(proj.resourceAccess[i.object]);
    case "resourceAccess.listGrantsArgs":
      return resourceAccess.listGrantsArgs(proj.resourceAccess[i.object], "rec1");
    case "resourceAccess.grantInsert":
      return resourceAccess.grantInsert(proj.resourceAccess[i.object], i.scope, i.resourceID, i.kind, i.principalID, i.access);
    case "resourceAccess.revokeDelete":
      return resourceAccess.revokeDelete(proj.resourceAccess[i.object], i.resourceID, i.kind, i.principalID, i.access);

    default:
      throw new Error(`oracle: unknown case kind "${c.kind}"`);
  }
}

describe("cross-language oracle — TS runtime over emitted projections == Go builders", () => {
  let total = 0;
  for (const [specName, entry] of Object.entries(oracle)) {
    describe(specName, () => {
      entry.cases.forEach((c, idx) => {
        total++;
        it(`${c.kind} #${idx}`, () => {
          expect(runCase(entry.projections, c)).toEqual(c.expect);
        });
      });
    });
  }
  it("covered a non-trivial number of cases across specs", () => {
    expect(total).toBeGreaterThan(80);
  });
});
