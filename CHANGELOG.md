# Changelog

All notable changes to LesS/KEY (the `hel` core and its `helwasm` web app) are
recorded here, newest first. The web app mirrors these entries in its in-app
"What's new" dialog (the footer version badge). Format follows
[Keep a Changelog](https://keepachangelog.com/); versions are the web app's
release stamp.

## [Unreleased] — A cache that forgets

Cut as 1.4.0 when the round is shipped (this section moves under a dated
heading and the in-app "What's new" entry is added then, so the footer badge
never claims a version that is not deployed).

### Added

- **Cached masters are encrypted in memory.** `pass` no longer keeps your
  master as a plain string for the session: each value is sealed with
  XChaCha20-Poly1305 under a random key that is re-minted on every expiry
  sweep, and the plaintext exists only for the moment a derivation needs it.
  This is about _residency_, not a security boundary — an attacker who can read
  the live process reads the key too. What it shortens is how long a master
  lingers where a core dump, a swapped page, a hibernation image or a browser
  heap snapshot can find it.
- **Cached masters can age out.** `set hel_pass_ttl 15m` forgets a master left
  unused that long; `set hel_pass_max_age 8h` forgets it that long after it was
  entered, used or not. Both are off by default, `0` switches one off, and a
  duration is a bare number of seconds (`900`) or a number with a unit (`45s`,
  `15m`, `2h`, `1d`). Expiry is checked before every command, and while the
  prompt sits idle a background sweep wipes what has aged out and says so
  without garbling what you are typing. The web tool runs the same sweep on a
  timer and clears the password it was showing.
- **`set hel_pass_lock_on_hide 1`** (web tool, off by default) drops every
  cached master the moment the app goes to the background.
- **`set` refuses a duration it cannot read.** `set hel_pass_ttl "quarter hour"`
  is an error instead of silently meaning "never expires" — the one typo that
  would disable the protection it was meant to enable.

### Changed

- **The web tool's master box is write-only.** What you type is pushed into the
  engine at the first commit (Enter, Copy, or leaving the box) and the box is
  emptied, so your master no longer sits in a readable input field for the whole
  session. An empty box still means "use the cached master"; the label says when
  one is held and offers to forget it.

### Fixed

- **`enc /` prints the root master** instead of "error: name / not found". A
  root (`/` or a `+name`) has its password entered, never derived, and needs no
  catalog entry — `enc +bohr` works the same way, and an uncached root now says
  so instead of reporting a missing name.
- **A bare `enc` explains itself** instead of printing the raw parser error.
- **Diagnostics are no longer masked as passwords in the web console.** The
  parser writes `error at L:C:`, which the console's `warning:`/`error:` test
  missed, so a parse error was rendered as a maskable secret; `note:` lines
  (which `enc` emits when several entries match) had the same problem.

## [1.3.3] - 2026-08-20 — Anchors that hold

### Fixed

- **`^` in `ls`/`ld` anchors where you expect it.** The pattern used to be
  tried against three haystacks per entry (descriptor line, bare name, bare
  comment) and any hit listed the entry, so `ls ^ssh` also matched entries
  whose COMMENT starts with `ssh`. Worse, the descriptor haystack is
  left-padded to a fixed prefix column, so `^` could never match there at
  all. The default scope is now the trimmed descriptor line only: `^`
  anchors at the name, `$` at the end of `^parent`. On a 1230-entry catalog
  `ls ^ssh` drops from 5 hits (2 real, 3 comment-start) to 2. Unanchored
  patterns are unchanged. Core: `cmd_ls` in `hel/src/commands.rs`.

### Added

- **Scope flags for `ls`/`ld`** — `ls [-n|-c|-l|-a] [regex]`:
  - none / `-l` — the whole trimmed descriptor line (default, as above)
  - `-n` — the bare name: `ls -n ^microsoft.*t$`
  - `-c` — the bare comment: `ls -c ^ok@`
  - `-a` — any of the three, each anchored on its own (the old behaviour)

  A flag counts only when a pattern follows it, so a bare `ls -n` still
  searches for the literal `-n`. Parser: `ls_scope`/`ls_args`; core:
  `LsScope` in `hel/src/structs.rs`.

## [1.3.2] - 2026-08-03 — Careful merges

### Changed

- **`add` of an existing name is a visible merge, not a bare error.** The
  stored entry still always wins (an import never overwrites), but instead
  of `error: password X already exist` a DIFFERING line now prints a
  dump-diff-style pair — `< stored (kept)` / `> incoming (ignored)` — while
  an identical line stays silent, so `source`-ing a dump you already have
  is quiet and a changed source is precisely visible. Applies everywhere
  `add` runs: CLI `source <file>` / `source <cmd>|`, web import, console.
  Take the incoming version deliberately via `rm` + re-add. Core:
  `cmd_add` in `hel/src/commands.rs`.
- Web import dialog understands the new pairs: a clean import with
  conflicts reports "N entries differ from your catalog — kept yours" with
  the first pairs inline (console holds the rest), and its hint no longer
  claims same-name entries are replaced (they never were).

### Added

- **`source -m <file-or-cmd|>`** (CLI + console): after the merge, list
  catalog names the source does NOT mention, one `- name` per line — a
  reverse diff to spot entries missing from e.g. the Notion page. Optional;
  plain `source` behaves as before. Parser: `source_cmd`; core:
  `cmd_source(missing, …)`.

## [1.3.1] - 2026-08-01 — An honest importer

### Fixed

- **Import failures are now visible.** The engine's script import is atomic
  (one unparseable line rejects the whole paste — the catalog is never
  half-replaced), but the web dialog always toasted "Imported". It now shows
  the engine's error lines in the dialog and stays open — explicitly saying
  "Nothing imported" on a wholesale parse reject — and a clean import
  reports the real catalog size ("Imported — catalog now N entries (+M)"),
  echoed to the console too.
- **CRLF pastes import.** The script grammar accepts `\r` only before a
  command, not before the `\n` separator, so a Windows-line-ending paste was
  rejected wholesale (and, before the fix above, silently). `extractScript`
  now normalizes `\r\n`/`\r` to `\n` first.
- **Unterminated final markdown fence keeps its lines.** A truncated page
  copy whose last code fence never closes silently dropped that block; the
  dangling block now counts as fence content and is imported.

## [1.3.0] - 2026-07-29 — Find anything, see everything

### Added

- **Regex catalog search in the name field.** `hel_names` now mirrors `ls`:
  the typed text is a regular expression matched anywhere in the full
  canonical stored line (`name [len]mode seq date comment ^parent` — the
  dump/export form), case-insensitive with `(?-i)` opt-out, `^`/`$`
  anchoring the whole line. A half-typed pattern that doesn't compile falls
  back to a literal substring match so the dropdown never flickers away.
  Still read-only over `db` values (never rebuilds `lk.ls`).
- **Rich suggestion rows.** Each suggestion shows the entry name (bold), its
  `^parent` beside it, and the start of the comment underneath, instead of
  the bare name.
- **Entry meta chips.** Under the name field, chips surface the stored
  entry's `^parent` (click jumps to that entry), plus the first http(s) URL
  and e-mail address parsed out of the comment — click to copy; the URL chip
  carries an `↗` link that opens the site.

### Fixed

- **`save` diff is always complete.** The `< removed` / `> added` diff now
  covers every unsaved change, always: with no baseline (nothing loaded yet)
  the whole catalog shows as added; a later `source` no longer resets the
  baseline, so imported entries appear in the diff (only the first load and
  each successful save move it — a `reset yes` + reimport shows its sealing
  changes too); a clean save prints `no changes since last load/save` instead
  of nothing.

## [1.2.0] - 2026-07-10 — One-time codes, and a real shell on your phone

### Added

- **TOTP one-time codes (2FA).** New mode `T` generates a time-based one-time
  code (RFC 6238) from an inline seed written `#"otpauth://…"` (or a bare base32
  secret); `enc <name>` prints the current six-digit code. Seeds are encrypted
  with a key derived from the entry and its master chain — the UNFOLDED iterated
  SHA-1 state (full 160 bits, so a strong master keeps its strength; the 64-bit
  word-fold never touches the key) through argon2id (64 MiB, t=16; ~0.5 s
  native, ~1 s in the browser) + XChaCha20-Poly1305, AAD-bound to the entry's
  name/seq/token-type — and never stored in the clear. The key ignores
  mode/prefix/length, so those edits never orphan a blob. `!"<text>"` stores an
  encrypted note, and `reveal <name>` decrypts the inline `#`/`!` blobs. Core:
  `hel/src/totp.rs`, `hel/src/crypto.rs`, `SKey::unfolded`.
- **`+` roots — multiple master passwords.** A name starting with `+` (e.g.
  `+bohr`) is an independent root: its password is entered (`pass +bohr` or a
  prompt), never derived, and the `^parent` chain stops there — a blank prompt
  will not climb past it. Compartmentalized subtrees under separate masters;
  `/` stays the unnamed default root with the same semantics.
- **`$` unfolded subtrees.** A base whose name starts with `$` (combinable as
  `+$vault`) switches its entire subtree to the UNFOLDED derivation: passwords
  render the full 160-bit value (15 words / 40 hex instead of 6 / 16) and
  chained masters keep the full width. Set once on the base — descendants
  inherit. Under a root with a long entered password this lifts the whole
  subtree (and its encrypted blobs) above the classic 64-bit S/KEY fold.
- **Name autocomplete.** The quick-generate name field suggests matching catalog
  entries as you type (read-only prefix match, case-insensitive; `(?-i)` forces
  case-sensitive), so re-entering a saved name is a tap. Backed by a new
  read-only `hel_names` WASM export.
- **Markdown import.** The Import box accepts a full markdown paste (e.g. a whole
  Notion page whose `dump` is split across fenced code blocks): only the code-block
  contents are imported, in order. Raw command text still works unchanged.
- **`rnd` command — mint root passwords.** `rnd[N] [descriptor]` prints N
  candidates from pure OS randomness: 160 fresh bits each, rendered full-width
  in the descriptor's mode/prefix/length (15 words for R, like a `$` entry). No
  master and no derivation involved — for creating new `+`/`+$` root passwords
  whose entropy must not descend from an existing master. `pb rnd1` copies one.
- **`reset` command.** `reset yes` drops the whole in-memory catalog for a clean
  reimport (`source` right after — cached masters are kept, so inline secrets
  seal without re-prompting). Nothing saved changes until the next `save`; a
  bare `reset` only prints the confirmation hint.
- **Bare `pass` = root master.** `pass` with no name now targets the root `/`
  (like `pass /`), in helcli (parser default) and the web console overlay (which
  titles it "Master password (root)"). `unpass` is unchanged (`unpass` still
  forgets all cached masters).
- **Hierarchy password prompt in the form.** Generating a `^parent`-derived name
  with an empty master field now walks the parent chain like the CLI's
  `read_master`: it asks for the immediate base's password, blank climbs to the
  base's base, up to the root master. An entered intermediate password is cached
  (same as `pass`, cleared when the master field changes). Backed by a new
  read-only `hel_chain` WASM export; the prompt reuses the `pass` modal.

### Changed

- **Mobile console shell.** On phones the console now fits the viewport and stays
  visible above the on-screen keyboard (via the `visualViewport` API) instead of
  being covered by it. Tapping a masked secret to reveal it keeps `#cin` focused,
  so the keyboard and shell stay open (`mousedown`/`touchend` preventDefault). A
  drag handle under the output resizes it, and the chosen height is remembered.
  Desktop behaviour is unchanged.

### Fixed

- `gen` table alignment with `$` (unfolded) names: the password column now grows
  to the widest listed password (15-word values overflowed the fixed 36-char
  column); narrow listings keep the classic layout.
- Hierarchy climb (web): a root master entered at the climb prompt is cached for
  the session (like `pass /`) instead of being written into the visible master
  field — the field only ever shows what you typed there yourself.
- Console masking + secret redaction (web): wide `$` (unfolded) passwords in
  `gen`/`rnd` output are now masked — the widened column had slipped past the fixed
  36-char mask window and rendered in the clear, and `rnd` rows were not masked at
  all. The web parser now derives the password column from the header row and masks
  both `gen` and `rnd` tables. `pass`/`set` long forms are also redacted in the
  console echo (`pass name ***`) and are never written to the persisted command
  history.

## [1.1.0] - 2026-06-14 — Updates itself, works offline

### Added

- The installed app updates itself the next time you open it — no more removing
  and re-adding — and the saved catalog is kept across updates.
- Runs fully offline once installed; everything is cached on the device.

### Changed

- `help` takes a topic: `help [topic]` gives a grouped overview plus per-command
  detail.
- `enc` takes a sub-command like `pb`: `enc ls` / `enc ld <regex>` encodes the
  matching entry, and `pb ld <regex>` copies its name.

## [1.0.0] - 2026-06-10 — Keyboard-first, and installable

### Added

- Press Enter in the name field to jump to the master; Enter in the master
  generates and copies.
- Install LesS/KEY to the home screen and run it as a standalone app.

### Changed

- Fresh ensō + key icon; the result shrinks to stay on one line on narrow phones.

## [0.9.0] - 2026-06-09 — A smarter catalog

### Added

- Quick password follows `^parent` chains, all computed from your one master.
- `pb` copies a command's output to the clipboard; `help` lists every command.

### Changed

- One progressive Store → Correct button; verified results show in colour.

## [0.8.0] - 2026-06-08 — Public launch

### Added

- Runs entirely in the browser via WebAssembly — nothing typed is ever sent to a
  server.
- Self-hosted fonts, installable and mobile-friendly; a bare name makes six
  memorable S/KEY words by default.
