/**
 * @demesne/runtime — the Demesne authorization runtime.
 *
 * Reproduces the Go engine's Layer-2 (read glue) and Layer-3 (control-plane write)
 * helpers from the same plain-data projection the engine emits. Zero runtime
 * dependencies; every SQL string and minted claims blob is byte-identical to the Go
 * side (proven by the differential golden oracle).
 */

export * from "./goCompat.js";
export * from "./decision.js";
export type * from "./types.js";
