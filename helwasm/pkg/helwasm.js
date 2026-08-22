/* @ts-self-types="./helwasm.d.ts" */

/**
 * Return the `^parent` chain of `name`, immediate parent first, one per line
 * ("" if `name` is unknown or has no parent). These are exactly the entries
 * `read_master` climbs through when deriving `name`: with no root master given,
 * the UI prompts for each in turn (the name's base, then the base's base, …).
 * Read-only; cycle-guarded.
 * @param {string} name
 * @returns {string}
 */
export function hel_chain(name) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.hel_chain(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Run a single hel command line and return its combined output.
 * @param {string} cmd
 * @returns {string}
 */
export function hel_command(cmd) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(cmd, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.hel_command(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Look up an entry by its exact name and return its canonical stored form
 * (`name [len]mode seq date comment ^parent`), or "" if it is not in the catalog.
 * Read-only. The UI uses this to detect "already stored" and to use the real stored
 * spec (its mode/seq/date/parent) instead of the bare name the user typed.
 * @param {string} name
 * @returns {string}
 */
export function hel_entry(name) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.hel_entry(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * A boolean setting as the engine sees it (`set <key> 1|true|yes|on`), so the
 * page can honour a config flag instead of keeping its own copy.
 * @param {string} key
 * @returns {boolean}
 */
export function hel_flag(key) {
    const ptr0 = passStringToWasm0(key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.hel_flag(ptr0, len0);
    return ret !== 0;
}

/**
 * True if a master/parent password is currently cached for `name` (what the
 * `pass` command stores, and what `unpass` drops). Presence only — the secret
 * itself never crosses the boundary. The page uses it to show whether a master
 * is held without keeping a copy of its own.
 * @param {string} name
 * @returns {boolean}
 */
export function hel_has_secret(name) {
    const ptr0 = passStringToWasm0(name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.hel_has_secret(ptr0, len0);
    return ret !== 0;
}

/**
 * Call once at page load: routes Rust panics to the browser console with a
 * readable message + stack instead of an opaque "unreachable" trap.
 */
export function hel_init() {
    wasm.hel_init();
}

/**
 * Run a whole multi-line script (every `add …` line, `set …`, etc.) against the
 * shared state in one call. Used to bulk-import a pasted catalog (e.g. the text
 * of the Notion page) and to load the persisted catalog from localStorage.
 * @param {string} script
 * @returns {string}
 */
export function hel_load_script(script) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(script, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.hel_load_script(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

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
 * @param {string} pattern
 * @returns {string}
 */
export function hel_names(pattern) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(pattern, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.hel_names(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Parse a password spec (e.g. `exa91` or `exa91 20R 99 2020-01-01`) and return
 * the canonical normalized form hel actually uses (name + mode + seq + date +
 * comment), without touching state. Returns the input unchanged if it does not
 * parse. Used by the UI to rewrite the name field on blur.
 * @param {string} spec
 * @returns {string}
 */
export function hel_parse(spec) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(spec, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.hel_parse(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Parse a spec and return just the entry name hel resolves it to. Handles a
 * leading prefix (e.g. `*P0 test1 …` → `test1`), which a naive first-token
 * split would get wrong. Falls back to the first whitespace token.
 * @param {string} spec
 * @returns {string}
 */
export function hel_parse_name(spec) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(spec, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.hel_parse_name(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * One expiry tick, driven by the page's timer (the browser is single-threaded,
 * so there is no sweeper thread here). Wipes every cached password that has
 * aged out and returns their names, one per line — "" when nothing went. Does
 * no work at all while both TTLs are off.
 * @returns {string}
 */
export function hel_tick() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.hel_tick();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_is_function_1ff95bcc5517c252: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_a27215656b807791: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_ea5e6cc2e4141dfe: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_c05833b95a3cf397: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_memory_de265df8aadd6273: function() {
            const ret = wasm.memory;
            return ret;
        },
        __wbg___wbindgen_throw_344f42d3211c4765: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_buffer_20eb5c4c035a2b02: function(arg0) {
            const ret = arg0.buffer;
            return ret;
        },
        __wbg_call_e1bb38bab8876690: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.call(arg1);
            return ret;
        }, arguments); },
        __wbg_call_f9b20945c2f1bfe3: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_crypto_f43a4c86a0c7157a: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_error_a6fa202b58aa1cd3: function(arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
            }
        },
        __wbg_getRandomValues_6b4be600718ac5c0: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_getTime_671f72cfc86ca804: function(arg0) {
            const ret = arg0.getTime();
            return ret;
        },
        __wbg_getTimezoneOffset_d480d50c444e5b45: function(arg0) {
            const ret = arg0.getTimezoneOffset();
            return ret;
        },
        __wbg_globalThis_6d5c691cd8302b28: function() { return handleError(function () {
            const ret = globalThis.globalThis;
            return ret;
        }, arguments); },
        __wbg_global_2621fef02ebf3494: function() { return handleError(function () {
            const ret = global.global;
            return ret;
        }, arguments); },
        __wbg_hel_clipboard_write_efa8177dd67c65ec: function(arg0, arg1) {
            hel_clipboard_write(getStringFromWasm0(arg0, arg1));
        },
        __wbg_hel_get_password_271a2beac04c29db: function(arg0, arg1, arg2) {
            const ret = hel_get_password(getStringFromWasm0(arg1, arg2));
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_hel_rnd_range_d01857a65a482c6d: function(arg0, arg1) {
            const ret = hel_rnd_range(arg0 >>> 0, arg1 >>> 0);
            return ret;
        },
        __wbg_hel_storage_get_9915f302e24bdacb: function(arg0, arg1, arg2) {
            const ret = hel_storage_get(getStringFromWasm0(arg1, arg2));
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_hel_storage_set_78052521669832fa: function(arg0, arg1, arg2, arg3) {
            hel_storage_set(getStringFromWasm0(arg0, arg1), getStringFromWasm0(arg2, arg3));
        },
        __wbg_length_563f2044099d4a23: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_msCrypto_9ff276969b3ab68c: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_new_0_0c17c8ed33a0e46a: function() {
            const ret = new Date();
            return ret;
        },
        __wbg_new_227d7c05414eb861: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_41c6bd634229343e: function(arg0) {
            const ret = new Date(arg0);
            return ret;
        },
        __wbg_new_5a8720951af575e8: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_no_args_af7ce56c0a943483: function(arg0, arg1) {
            const ret = new Function(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_with_length_1d0fa3912516a1a7: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_node_112d6e6b60d5ad71: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_process_71594fb16469954f: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_randomFillSync_57af018321fe5242: function() { return handleError(function (arg0, arg1, arg2) {
            arg0.randomFillSync(getArrayU8FromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_require_fce86418f1f47c91: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_self_4d13fca7e70dc961: function() { return handleError(function () {
            const ret = self.self;
            return ret;
        }, arguments); },
        __wbg_set_3965876d3f9128ce: function(arg0, arg1, arg2) {
            arg0.set(arg1, arg2 >>> 0);
        },
        __wbg_stack_3b0d974bbf31e44f: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_subarray_6ecaf2270e9d1ab5: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_versions_1d7e019137ae42fd: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbg_window_aedc18e26f22b6c8: function() { return handleError(function () {
            const ret = window.window;
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000001: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./helwasm_bg.js": import0,
    };
}

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('helwasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
