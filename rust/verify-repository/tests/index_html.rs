use std::collections::HashMap;

const INDEX_HTML: &str = include_str!("../../../index.html");
const CANONICAL_URL: &str = "https://chr0nict.github.io/Nepeta-Mirror/";

fn logo_anchor(html: &str) -> Option<&str> {
    let start = html.find("<a class=\"logo\"")?;
    let bytes = html.as_bytes();
    let mut quote = None;
    for index in start..bytes.len() {
        match (quote, bytes[index]) {
            (Some(open), byte) if open == byte => quote = None,
            (None, byte @ (b'\'' | b'\"')) => quote = Some(byte),
            (None, b'>') => return Some(&html[start..=index]),
            _ => {}
        }
    }
    None
}

fn parse_anchor_attributes(tag: &str) -> Option<HashMap<String, String>> {
    if !tag.is_ascii() || !tag.starts_with("<a") || !tag.ends_with('>') {
        return None;
    }
    let bytes = tag.as_bytes();
    let mut index = 2;
    let mut attributes = HashMap::new();

    loop {
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            index += 1;
        }
        if index == bytes.len() - 1 {
            return Some(attributes);
        }

        let start = index;
        if !bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b':'))
        {
            return None;
        }
        index += 1;
        while bytes.get(index).is_some_and(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.')
        }) {
            index += 1;
        }
        let name = tag[start..index].to_ascii_lowercase();
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            index += 1;
        }
        if bytes.get(index) != Some(&b'=') {
            return None;
        }
        index += 1;
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            index += 1;
        }

        let quote = *bytes.get(index)?;
        if !matches!(quote, b'\'' | b'\"') {
            return None;
        }
        index += 1;
        let value_start = index;
        while bytes.get(index).is_some_and(|byte| *byte != quote) {
            if bytes[index] == b'<' {
                return None;
            }
            index += 1;
        }
        if index == bytes.len() {
            return None;
        }
        let value = tag[value_start..index].to_string();
        index += 1;
        if attributes.insert(name, value).is_some() {
            return None;
        }
    }
}

#[test]
fn logo_anchor_parser_rejects_the_reported_malformed_attribute() {
    let malformed = r#"<a class="logo" href="https://example.test/" "="">"#;
    assert!(parse_anchor_attributes(malformed).is_none());
}

#[test]
fn landing_page_logo_markup_matches_its_canonical_url() {
    assert!(INDEX_HTML
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("<!doctype html>"));

    let logo = logo_anchor(INDEX_HTML).and_then(parse_anchor_attributes);
    let logo = logo.expect("logo anchor should have well-formed quoted attributes");
    assert_eq!(
        logo.len(),
        2,
        "logo anchor should contain only class and href"
    );
    assert_eq!(logo.get("class").map(String::as_str), Some("logo"));
    assert_eq!(logo.get("href").map(String::as_str), Some(CANONICAL_URL));
    assert!(INDEX_HTML.contains(&format!(
        "<meta property=\"og:url\" content=\"{CANONICAL_URL}\">"
    )));
}
