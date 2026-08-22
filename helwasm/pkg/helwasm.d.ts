/* tslint:disable */
/* eslint-disable */

/**
 * Return the `^parent` chain of `name`, immediate parent first, one per line
 * ("" if `name` is unknown or has no parent). These are exactly the entries
 * `read_master` climbs through when deriving `name`: with no root master given,
 * the UI prompts for each in turn (the name's base, then the base's base, …).
 * Read-only; cycle-guarded.
 */
export function hel_chain(name: string): string;

/**
 * Run a single hel command line and return its combined output.
 */
export function hel_command(cmd: string): string;

/**
 * Look up an entry by its exact name and return its canonical stored form
 * (`name [len]mode seq date comment ^parent`), or "" if it is not in the catalog.
 * Read-only. The UI uses this to detect "already stored" and to use the real stored
 * spec (its mode/seq/date/parent) instead of the bare name the user typed.
 */
export function hel_entry(name: string): string;

/**
 * A boolean setting as the engine sees it (`set <key> 1|true|yes|on`), so the
 * page can honour a config flag instead of keeping its own copy.
 */
export function hel_flag(key: string): boolean;

/**
 * True if a master/parent password is currently cached for `name` (what the
 * `pass` command stores, and what `unpass` drops). Presence only — the secret
 * itself never crosses the boundary. The page uses it to show whether a master
 * is held without keeping a copy of its own.
 */
export function hel_has_secret(name: string): boolean;

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

/**
 * Return catalog entries matching `pattern`, one canonical stored line per
 * line (`name [len]mode seq date comment ^parent` — the dump/export form),
 * sorted — the completion set for a typed name. The pattern is a regular
 * expression matched anywhere in the full canonical line, mirroring `ls`
 * (so `^`/`$` anchor against the whole line, and mode/comment/parent are
 * searchable too). Case-insensitive by default; a leading `(?-i)` forces
 * case-sensitive, exactly like `ls`. A pattern that does not compile (e.g.
 * a half-typed `micro(`) falls back to a literal substring match, so
 * suggestions never vanish mid-keystroke. Read-only: reads `db` values
 * only, so (unlike `ls`) it never rebuilds `lk.ls` or mutates state, and
 * can never add to the catalog.
 */
export function hel_names(pattern: string): string;

/**
 * Parse a password spec (e.g. `exa91` or `exa91 20R 99 2020-01-01`) and return
 * the canonical normalized form hel actually uses (name + mode + seq + date +
 * comment), without touching state. Returns the input unchanged if it does not
 * parse. Used by the UI to rewrite the name field on blur.
 */
export function hel_parse(spec: string): string;

/**
 * Parse a spec and return just the entry name hel resolves it to. Handles a
 * leading prefix (e.g. `*P0 test1 …` → `test1`), which a naive first-token
 * split would get wrong. Falls back to the first whitespace token.
 */
export function hel_parse_name(spec: string): string;

/**
 * One expiry tick, driven by the page's timer (the browser is single-threaded,
 * so there is no sweeper thread here). Wipes every cached password that has
 * aged out and returns their names, one per line — "" when nothing went. Does
 * no work at all while both TTLs are off.
 */
export function hel_tick(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly hel_init: () => void;
    readonly hel_chain: (a: number, b: number) => [number, number];
    readonly hel_command: (a: number, b: number) => [number, number];
    readonly hel_entry: (a: number, b: number) => [number, number];
    readonly hel_flag: (a: number, b: number) => number;
    readonly hel_has_secret: (a: number, b: number) => number;
    readonly hel_load_script: (a: number, b: number) => [number, number];
    readonly hel_names: (a: number, b: number) => [number, number];
    readonly hel_parse: (a: number, b: number) => [number, number];
    readonly hel_parse_name: (a: number, b: number) => [number, number];
    readonly hel_tick: () => [number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
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
