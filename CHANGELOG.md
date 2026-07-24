# Changelog

All notable changes to LesS/KEY (the `hel` core and its `helwasm` web app) are
recorded here, newest first. The web app mirrors these entries in its in-app
"What's new" dialog (the footer version badge). Format follows
[Keep a Changelog](https://keepachangelog.com/); versions are the web app's
release stamp.

## [Unreleased]

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
