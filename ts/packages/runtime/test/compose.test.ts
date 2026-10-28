import { describe, it, expect } from "vitest";
import { composeCan, Decision } from "../src/index.js";

describe("composeCan composes a point check with the PDP as the Go engine does", () => {
  const { Allow, Deny, NotGoverned } = Decision;
  const cases: Array<[boolean, boolean, string, string]> = [
    [true, true, Allow, Allow],
    [true, true, Deny, Deny],
    [true, true, NotGoverned, Allow],
    [true, false, Allow, Deny],
    [true, false, Deny, Deny],
    [true, false, NotGoverned, Deny],
    [false, true, Allow, Allow],
    [false, true, Deny, Deny],
    [false, true, NotGoverned, NotGoverned],
    [false, false, Allow, Allow],
    [false, false, Deny, Deny],
    [false, false, NotGoverned, NotGoverned],
  ];
  it.each(cases)("governed %s, allowed %s, PDP %s gives %s", (governed, allowed, pdp, want) => {
    expect(composeCan(governed, allowed, pdp as Decision)).toBe(want);
  });
});
