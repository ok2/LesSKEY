# Hel: password generator and manager

Hel is a password manager which newer stores the passwords but generates them according to the rules from the master password and the given name of the password.

## Commands & behavior

- `ls <regex>` matches **case-insensitively** (name, full line, and comment). Add
  an inline `(?-i)` to the pattern to force case-sensitive.
- `source <file|command|>` echoes `source <target>` so you see what was loaded.
- `save` prints a diff against the previously loaded/saved snapshot before
  persisting: `< line` = removed, `> line` = added — so an accidental removal is
  visible on the save that would persist it. (Set-based, so dump ordering is
  irrelevant.) The baseline is seeded on startup load and refreshed on each save.

## Persistence

Hel never stores secrets — only the entry catalog (names + generation rules),
which is a script of `add …` lines. That script can be saved to / loaded from a
file, an external command, or a **Notion** page.

### `set`: configuration from `~/.helrc`

Instead of environment variables, settings can live in the init script via
`set <key> <value>`:

```
set hel_dump |hel store notion:somenote
set hel_notion_token secret_xxxxxxxx
source hel load notion:somenote|
```

- Keys are case-insensitive. A `set` is never written to the shell history, and
  its value is redacted in any echo (it may be a secret token).
- Lookups check the `set` map first, then the matching `UPPERCASE` environment
  variable. So `set hel_dump …` overrides `$HEL_DUMP`, etc.
- When hel runs a pipe/source command, the whole `set` map is exported (uppercased)
  into that child process — that is how `set hel_notion_token …` reaches a spawned
  `hel store` / `hel load`.

### Notion backend

The `hel` binary doubles as the Notion backend through two non-interactive
subcommands, designed to drop into the existing pipe plumbing:

- `hel store notion:<ref>` — read the dump from **stdin** and write it into the
  Notion page (one code block, replaced in place).
- `hel load notion:<ref>` — fetch the page and print the dump to **stdout**.

`<ref>` is either a Notion page id (UUID) or a page **title** (resolved by search).
The integration token comes from `HEL_NOTION_TOKEN` (or `set hel_notion_token …`),
and the target page must be shared with that integration.

Wire it up so `save` pushes to Notion and startup pulls from it:

```
# ~/.helrc
set hel_notion_token secret_xxxxxxxx
set hel_dump |hel store notion:somenote
source hel load notion:somenote|
```

(Equivalently, `export HEL_DUMP="|hel store notion:somenote"` and
`export HEL_NOTION_TOKEN=…` in the shell.)
