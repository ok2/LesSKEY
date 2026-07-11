//! Minimal Notion REST client for the `hel store` / `hel load` subcommands.
//!
//! The hel dump is a runnable `add …` script; this module parks the script in
//! **code blocks** on one Notion page and reads it back (their texts
//! concatenated in page order — a legacy single-block page reads the same).
//! Writes go in segments of at most `MAX_BLOCK_CHARS`: Notion's gateway 504s
//! on big single-block updates (processing scales with block size, the CDN
//! cuts at ~100 s), while several small PATCHes go through reliably. The page
//! is addressed by `notion:<ref>` where `<ref>` is either a page id (UUID,
//! dashed or bare) or a page title resolved via Notion search.
//!
//! Auth: an internal-integration token from `HEL_NOTION_TOKEN`. The page must be
//! shared with that integration. All code blocks on the page belong to hel.

use serde_json::{json, Value};

const API: &str = "https://api.notion.com/v1";
const NOTION_VERSION: &str = "2022-06-28";
/// Notion caps a single rich_text `content` at 2000 characters.
const MAX_RICH_TEXT: usize = 2000;
/// Per-code-block content budget for writes (10 rich_text chunks). A full
/// catalog (~115 KB) becomes ~6 fast PATCHes instead of one 504-prone giant.
const MAX_BLOCK_CHARS: usize = 20_000;

/// Split `notion:<ref>` into its reference part, rejecting other schemes.
pub fn parse_target(target: &str) -> Result<&str, String> {
    match target.split_once(':') {
        Some(("notion", r)) if !r.is_empty() => Ok(r),
        _ => Err(format!(
            "unsupported target {:?}; expected notion:<page-title-or-id>",
            target
        )),
    }
}

/// True if `s` is a 32-hex Notion page id (dashed UUID or bare hex).
pub fn is_uuid(s: &str) -> bool {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    hex.len() == 32 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// Split `text` into `{type:text, text:{content}}` rich_text items, each at most
/// `MAX_RICH_TEXT` characters. Splits on char boundaries so multibyte stays intact.
pub fn chunk_rich_text(text: &str) -> Vec<Value> {
    if text.is_empty() {
        return vec![json!({ "type": "text", "text": { "content": "" } })];
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let end = std::cmp::min(i + MAX_RICH_TEXT, chars.len());
        let chunk: String = chars[i..end].iter().collect();
        out.push(json!({ "type": "text", "text": { "content": chunk } }));
        i = end;
    }
    out
}

/// Split `text` into write segments of at most `max` characters, cutting after
/// a newline whenever one fits the budget (hard char-split only for a single
/// oversize line). Concatenating the segments reproduces `text` exactly.
pub fn split_segments(text: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut seg = String::new();
    let mut seg_chars = 0usize;
    for piece in text.split_inclusive('\n') {
        let mut rest = piece;
        let mut rest_chars = rest.chars().count();
        // an oversize single line: flush, then emit max-sized slices directly
        while rest_chars > max {
            if seg_chars > 0 {
                out.push(std::mem::take(&mut seg));
                seg_chars = 0;
            }
            let cut = rest.char_indices().nth(max).map(|(i, _)| i).unwrap_or(rest.len());
            out.push(rest[..cut].to_string());
            rest = &rest[cut..];
            rest_chars -= max;
        }
        if seg_chars + rest_chars > max {
            out.push(std::mem::take(&mut seg));
            seg_chars = 0;
        }
        seg.push_str(rest);
        seg_chars += rest_chars;
    }
    if !seg.is_empty() || out.is_empty() {
        out.push(seg);
    }
    out
}

/// Plain text of a `code` block, concatenating its rich_text segments.
fn code_text(block: &Value) -> String {
    block["code"]["rich_text"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|rt| rt["plain_text"].as_str())
                .collect::<String>()
        })
        .unwrap_or_default()
}

/// Title of a page object: the value of its `title`-typed property, joined.
fn page_title(page: &Value) -> Option<String> {
    let props = page.get("properties")?.as_object()?;
    for v in props.values() {
        if v.get("type").and_then(Value::as_str) == Some("title") {
            let arr = v.get("title")?.as_array()?;
            return Some(
                arr.iter()
                    .filter_map(|rt| rt.get("plain_text").and_then(Value::as_str))
                    .collect(),
            );
        }
    }
    None
}

fn fmt_err(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            format!("Notion API HTTP {}: {}", code, body.trim())
        }
        ureq::Error::Transport(t) => format!("Notion request failed: {}", t),
    }
}

/// Send a request with up to two retries on a 5xx/429 status or a transport
/// error. Notion's gateway 504s on large writes and rate-limits bursts (429);
/// every request we make is idempotent, so retrying is safe. Other 4xx (auth,
/// not-found, validation) fails immediately.
fn send_retry(what: &str, f: impl Fn() -> Result<ureq::Response, ureq::Error>) -> Result<ureq::Response, String> {
    let mut delay = 2u64;
    let mut attempt = 0;
    loop {
        match f() {
            Ok(r) => return Ok(r),
            Err(ureq::Error::Status(code, _)) if (code >= 500 || code == 429) && attempt < 2 => {
                eprintln!("hel: Notion HTTP {} on {} — retrying in {}s", code, what, delay);
            }
            Err(ureq::Error::Transport(t)) if attempt < 2 => {
                eprintln!("hel: Notion request failed on {} ({}) — retrying in {}s", what, t, delay);
            }
            Err(e) => return Err(fmt_err(e)),
        }
        std::thread::sleep(std::time::Duration::from_secs(delay));
        delay *= 3;
        attempt += 1;
    }
}

pub struct Notion {
    token: String,
}

impl Notion {
    pub fn from_env() -> Result<Self, String> {
        match std::env::var("HEL_NOTION_TOKEN") {
            Ok(t) if !t.trim().is_empty() => Ok(Self { token: t }),
            _ => Err("HEL_NOTION_TOKEN is not set (use `set hel_notion_token …` or export it)".to_string()),
        }
    }

    fn req(&self, method: &str, url: &str) -> ureq::Request {
        ureq::request(method, url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Notion-Version", NOTION_VERSION)
    }

    /// Resolve `notion:<ref>` to a page id: a UUID is used directly; otherwise
    /// search for a page whose title matches `reference` exactly.
    pub fn resolve_page(&self, reference: &str) -> Result<String, String> {
        if is_uuid(reference) {
            return Ok(reference.to_string());
        }
        let resp: Value = send_retry("search", || {
            self.req("POST", &format!("{}/search", API)).send_json(json!({
                "query": reference,
                "filter": { "value": "page", "property": "object" }
            }))
        })?
        .into_json()
        .map_err(|e| e.to_string())?;

        let empty = Vec::new();
        let results = resp["results"].as_array().unwrap_or(&empty);
        // Match the title case-insensitively so `notion:hel` finds a page titled "HEL".
        let want = reference.to_lowercase();
        let mut matches: Vec<String> = results
            .iter()
            .filter(|p| page_title(p).map(|t| t.to_lowercase()).as_deref() == Some(want.as_str()))
            .filter_map(|p| p["id"].as_str().map(str::to_string))
            .collect();

        match matches.len() {
            0 => Err(format!(
                "no Notion page titled {:?} is shared with the integration",
                reference
            )),
            1 => Ok(matches.remove(0)),
            n => Err(format!(
                "{} Notion pages titled {:?}; address it by page id instead",
                n, reference
            )),
        }
    }

    /// All child blocks of a page (following pagination).
    fn children(&self, page_id: &str) -> Result<Vec<Value>, String> {
        let mut blocks = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut url = format!("{}/blocks/{}/children?page_size=100", API, page_id);
            if let Some(c) = &cursor {
                url.push_str("&start_cursor=");
                url.push_str(c);
            }
            let resp: Value = send_retry("list blocks", || self.req("GET", &url).call())?
                .into_json()
                .map_err(|e| e.to_string())?;
            if let Some(results) = resp["results"].as_array() {
                blocks.extend(results.iter().cloned());
            }
            if resp["has_more"].as_bool() == Some(true) {
                match resp["next_cursor"].as_str() {
                    Some(c) => cursor = Some(c.to_string()),
                    None => break,
                }
            } else {
                break;
            }
        }
        Ok(blocks)
    }

    /// Read the dump script back: the page's code blocks concatenated in page
    /// order. A legacy single-block page reads identically.
    pub fn read_dump(&self, page_id: &str) -> Result<String, String> {
        let children = self.children(page_id)?;
        Ok(children
            .iter()
            .filter(|b| b["type"].as_str() == Some("code"))
            .map(code_text)
            .collect())
    }

    /// Write the dump script across the page's code blocks, one segment of at
    /// most `MAX_BLOCK_CHARS` each (see the module docs: one giant block 504s).
    /// Existing code blocks are PATCHed in order; extra segments are appended;
    /// leftover blocks are deleted. Interleaved non-code content is untouched.
    pub fn write_dump(&self, page_id: &str, text: &str) -> Result<(), String> {
        let children = self.children(page_id)?;
        let segments = split_segments(text, MAX_BLOCK_CHARS);
        let existing: Vec<&str> = children
            .iter()
            .filter(|b| b["type"].as_str() == Some("code"))
            .filter_map(|b| b["id"].as_str())
            .collect();

        for (i, seg) in segments.iter().enumerate() {
            let rich_text = chunk_rich_text(seg);
            if let Some(block_id) = existing.get(i) {
                send_retry("write dump", || {
                    self.req("PATCH", &format!("{}/blocks/{}", API, block_id))
                        .send_json(json!({ "code": { "rich_text": rich_text } }))
                })?;
            } else {
                send_retry("write dump", || {
                    self.req("PATCH", &format!("{}/blocks/{}/children", API, page_id)).send_json(json!({
                        "children": [{
                            "type": "code",
                            "code": { "rich_text": rich_text, "language": "plain text" }
                        }]
                    }))
                })?;
            }
        }
        for block_id in existing.iter().skip(segments.len()) {
            send_retry("trim dump blocks", || {
                self.req("DELETE", &format!("{}/blocks/{}", API, block_id)).call()
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_ok() {
        assert_eq!(parse_target("notion:hel"), Ok("hel"));
        assert_eq!(parse_target("notion:My Page"), Ok("My Page"));
        assert_eq!(
            parse_target("notion:1234abcd1234abcd1234abcd1234abcd"),
            Ok("1234abcd1234abcd1234abcd1234abcd")
        );
    }

    #[test]
    fn parse_target_err() {
        assert!(parse_target("evernote:hel").is_err());
        assert!(parse_target("notion:").is_err());
        assert!(parse_target("hel").is_err());
    }

    #[test]
    fn uuid_detection() {
        assert!(is_uuid("11111111111111111111111111111111"));
        assert!(is_uuid("11111111-1111-1111-1111-111111111111"));
        assert!(!is_uuid("hel"));
        assert!(!is_uuid("1111")); // too short
        assert!(!is_uuid("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")); // non-hex
    }

    #[test]
    fn chunk_small_is_single() {
        let v = chunk_rich_text("add foo R 0 2026-01-01");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["text"]["content"], "add foo R 0 2026-01-01");
    }

    #[test]
    fn chunk_large_splits_under_limit() {
        let big = "x".repeat(MAX_RICH_TEXT * 2 + 5);
        let v = chunk_rich_text(&big);
        assert_eq!(v.len(), 3);
        for item in &v {
            let len = item["text"]["content"].as_str().unwrap().chars().count();
            assert!(len <= MAX_RICH_TEXT);
        }
        let joined: String = v
            .iter()
            .map(|i| i["text"]["content"].as_str().unwrap())
            .collect();
        assert_eq!(joined, big);
    }

    #[test]
    fn chunk_empty() {
        let v = chunk_rich_text("");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["text"]["content"], "");
    }

    #[test]
    fn split_segments_reassembles_exactly() {
        // line-shaped content like a dump: segments cut after newlines, and
        // concatenation reproduces the input byte-for-byte.
        let text: String = (0..500).map(|i| format!("add entry{} R 99 2026-01-01 #blobblobblob\n", i)).collect();
        let segs = split_segments(&text, 1000);
        assert!(segs.len() > 1);
        for s in &segs {
            assert!(s.chars().count() <= 1000);
            assert!(s.ends_with('\n')); // cut on line boundaries
        }
        assert_eq!(segs.concat(), text);
    }

    #[test]
    fn split_segments_small_and_empty() {
        assert_eq!(split_segments("one line\n", 1000), vec!["one line\n"]);
        assert_eq!(split_segments("", 1000), vec![""]);
    }

    #[test]
    fn split_segments_oversize_line() {
        // a single line longer than the budget hard-splits but still reassembles
        let long = "x".repeat(2500);
        let text = format!("short\n{}\ntail\n", long);
        let segs = split_segments(&text, 1000);
        for s in &segs {
            assert!(s.chars().count() <= 1000);
        }
        assert_eq!(segs.concat(), text);
    }
}
