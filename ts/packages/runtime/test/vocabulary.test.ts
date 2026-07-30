import { describe, it, expect } from "vitest";
import {
  presetPermissions,
  impliedPermissions,
  expandImplications,
  rankOf,
  presetsAtOrAbove,
  type Vocabulary,
} from "../src/index.js";
import { rolesVocab, manageVocab } from "./fixtures.js";

describe("presetPermissions — preset → flat permission set (sorted, deduped)", () => {
  it("viewer", () => {
    expect(presetPermissions(rolesVocab, "viewer")).toEqual(["admin:read", "docs:read"]);
  });
  it("editor (nested: includes viewer)", () => {
    expect(presetPermissions(rolesVocab, "editor")).toEqual([
      "admin:read",
      "docs:publish",
      "docs:read",
      "docs:write",
    ]);
  });
  it("owner (* → the whole vocabulary)", () => {
    expect(presetPermissions(rolesVocab, "owner")).toEqual([
      "admin:read",
      "admin:write",
      "docs:publish",
      "docs:read",
      "docs:write",
    ]);
  });
});

describe("presetPermissions — fail-closed errors", () => {
  it("throws on an unknown preset", () => {
    expect(() => presetPermissions(rolesVocab, "nope")).toThrow(/no preset/);
  });
  it("throws on a reference to neither a permission nor a preset", () => {
    const bad: Vocabulary = {
      name: "v",
      permissions: ["a:read"],
      presets: [{ name: "p", star: false, set: ["a:read", "ghost"] }],
      rank: [],
    };
    expect(() => presetPermissions(bad, "p")).toThrow(/neither a permission nor a preset/);
  });
  it("throws on a direct self-cycle", () => {
    const selfCycle: Vocabulary = {
      name: "v",
      permissions: [],
      presets: [{ name: "p", star: false, set: ["p"] }],
      rank: [],
    };
    expect(() => presetPermissions(selfCycle, "p")).toThrow(/cyclic/);
  });
  it("throws on a transitive cycle", () => {
    const transitive: Vocabulary = {
      name: "v",
      permissions: [],
      presets: [
        { name: "a", star: false, set: ["b"] },
        { name: "b", star: false, set: ["a"] },
      ],
      rank: [],
    };
    expect(() => presetPermissions(transitive, "a")).toThrow(/cyclic/);
  });
});

describe("impliedPermissions — transitive closure with wildcard and star items", () => {
  it("platform:manage (star) is the whole vocabulary", () => {
    expect(impliedPermissions(manageVocab, "platform:manage")).toEqual(
      manageVocab.permissions.slice().sort(),
    );
  });
  it("tenant:manage expands its list, its wildcards, and the next hop", () => {
    expect(impliedPermissions(manageVocab, "tenant:manage")).toEqual([
      "billing:read",
      "billing:write",
      "content:publish",
      "content:read",
      "invitations:read",
      "invitations:write",
      "project:manage",
      "records:read",
      "records:write",
      "tenant:manage",
    ]);
  });
  it("project:manage stops at its own ceiling", () => {
    expect(impliedPermissions(manageVocab, "project:manage")).toEqual([
      "content:publish",
      "content:read",
      "project:manage",
      "records:read",
      "records:write",
    ]);
  });
  it("a leaf verb implies only itself", () => {
    expect(impliedPermissions(manageVocab, "records:read")).toEqual(["records:read"]);
  });
  it("a cycle throws", () => {
    const cyclic: Vocabulary = {
      name: "v",
      permissions: ["a:manage", "b:manage"],
      implications: [
        { perm: "a:manage", star: false, set: ["b:manage"] },
        { perm: "b:manage", star: false, set: ["a:manage"] },
      ],
      presets: [],
      rank: [],
    };
    expect(() => impliedPermissions(cyclic, "a:manage")).toThrow(/cyclic/);
  });
  it("an unknown implication target throws", () => {
    const bad: Vocabulary = {
      name: "v",
      permissions: ["a:manage"],
      implications: [{ perm: "a:manage", star: false, set: ["ghost:read"] }],
      presets: [],
      rank: [],
    };
    expect(() => impliedPermissions(bad, "a:manage")).toThrow(/neither a permission/);
  });
  it("expandImplications is a no-op for a vocabulary without implications", () => {
    expect(expandImplications(rolesVocab, ["docs:read"])).toEqual(["docs:read"]);
  });
});

describe("rank helpers", () => {
  it("rankOf returns index + ok", () => {
    expect(rankOf(rolesVocab, "owner")).toEqual({ index: 0, ok: true });
    expect(rankOf(rolesVocab, "viewer")).toEqual({ index: 2, ok: true });
    expect(rankOf(rolesVocab, "ghost")).toEqual({ index: 0, ok: false });
  });
  it("presetsAtOrAbove returns the threshold and everything above it, ladder order", () => {
    expect(presetsAtOrAbove(rolesVocab, "editor")).toEqual(["owner", "editor"]);
    expect(presetsAtOrAbove(rolesVocab, "owner")).toEqual(["owner"]);
    expect(presetsAtOrAbove(rolesVocab, "ghost")).toEqual([]);
  });
});
