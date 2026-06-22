import { describe, it, expect } from "vitest";
import { authorize, composeCan, Decision } from "../src/index.js";
import { adminPdp } from "./fixtures.js";

// Ports runtime_test.go: TestComposeCan (the 8-row truth table) + TestRuntime_PDPAuthorize.

describe("composeCan — the 8-row truth table (branch order is load-bearing)", () => {
  const cases: Array<[string, boolean, boolean, Decision, Decision]> = [
    ["neither governs", false, false, Decision.NotGoverned, Decision.NotGoverned],
    ["row governs + passes", true, true, Decision.NotGoverned, Decision.Allow],
    ["row governs + fails", true, false, Decision.NotGoverned, Decision.Deny],
    ["pdp denies (no row)", false, false, Decision.Deny, Decision.Deny],
    ["pdp allows (no row)", false, false, Decision.Allow, Decision.Allow],
    ["row passes + pdp allows", true, true, Decision.Allow, Decision.Allow],
    ["row passes but pdp denies", true, true, Decision.Deny, Decision.Deny],
    ["row fails but pdp allows", true, false, Decision.Allow, Decision.Deny],
  ];
  it.each(cases)("%s", (_name, pointGoverned, pointAllow, pdp, want) => {
    expect(composeCan(pointGoverned, pointAllow, pdp)).toBe(want);
  });
});

describe("authorize — governed vs exempt vs unlisted", () => {
  const hasWrite = (perm: string) => perm === "content:write";
  const noPerm = () => false;
  const proc = "records.v1.RecordsService/UpdateRecord";

  it("allows a holder of the required permission", () => {
    expect(authorize(adminPdp, proc, hasWrite)).toBe(Decision.Allow);
  });
  it("denies a caller lacking the required permission", () => {
    expect(authorize(adminPdp, proc, noPerm)).toBe(Decision.Deny);
  });
  it("reports an exempt procedure as NotGoverned", () => {
    expect(authorize(adminPdp, "records.v1.RecordsService/GetRecord", noPerm)).toBe(Decision.NotGoverned);
  });
  it("reports an unlisted procedure as NotGoverned", () => {
    expect(authorize(adminPdp, "records.v1.RecordsService/Unknown", hasWrite)).toBe(Decision.NotGoverned);
  });
});
