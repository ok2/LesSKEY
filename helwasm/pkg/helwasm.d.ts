/* tslint:disable */
/* eslint-disable */

/**
 * Run a single hel command line and return its combined output.
 */
export function hel_command(cmd: string): string;

/**
 * Call once at page load: routes Rust panics to the browser console with a
 * readable message + stack instead of an opaque "unreachable" trap.
 */
export function hel_init(): void;

/**
 * Run a whole multi-line script (every `add …` line, `set …`, etc.) against the
 * shared state in one call. Used to bulk-import a pasted catalog (e.g. the text
 * of the Notion page) and to load the persisted catalog from localStorage.
 */
export function hel_load_script(script: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly hel_command: (a: number, b: number) => [number, number];
    readonly hel_init: () => void;
    readonly hel_load_script: (a: number, b: number) => [number, number];
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
