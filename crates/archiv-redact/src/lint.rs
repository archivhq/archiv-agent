//! Policy lint banning unbounded nested repetition (`core/04` §3): patterns
//! like `(a+)+` or `(?:\d+){3,}` where an unbounded quantifier applies to a
//! group that itself contains an unbounded quantifier. The `regex` crate has
//! no catastrophic backtracking (finite automata), but such patterns still
//! blow up compiled-program size and per-record cost — reject them at policy
//! validation, before they reach the fleet.
//!
//! Conservative single-pass scan: escapes (`\x`) and character classes
//! (`[...]`) are handled; anything the scanner cannot prove safe is left to
//! `RegexBuilder::size_limit` as the backstop.

/// Returns `Err(detail)` when an unbounded quantifier is applied to a group
/// containing an unbounded quantifier.
pub fn check_nested_repetition(pattern: &str) -> Result<(), &'static str> {
    let bytes = pattern.as_bytes();
    let mut i = 0usize;
    // One frame per open group: does it (transitively) contain an unbounded
    // quantifier? Index 0 is the pattern's top level.
    let mut frames: Vec<bool> = vec![false];

    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 1, // skip escaped char
            b'[' => {
                // Skip the character class; ']' as first member is literal.
                i += 1;
                if i < bytes.len() && bytes[i] == b'^' {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b']' {
                    i += 1;
                }
                while i < bytes.len() && bytes[i] != b']' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'(' => frames.push(false),
            b')' => {
                let inner_unbounded = frames.pop().unwrap_or(false);
                let (quant_unbounded, quant_len) = quantifier_at(bytes, i + 1);
                if quant_unbounded && inner_unbounded {
                    return Err(
                        "unbounded quantifier applied to a group containing an unbounded quantifier",
                    );
                }
                // The group's content (and its own repetition) folds into the parent.
                if let Some(parent) = frames.last_mut() {
                    *parent |= inner_unbounded || quant_unbounded;
                }
                i += quant_len;
            }
            b'*' | b'+' => {
                if let Some(top) = frames.last_mut() {
                    *top = true;
                }
            }
            b'{' => {
                let (unbounded, len) = brace_quantifier(bytes, i);
                if unbounded {
                    if let Some(top) = frames.last_mut() {
                        *top = true;
                    }
                }
                i += len.saturating_sub(1); // main loop advances the final byte
            }
            _ => {}
        }
        i += 1;
    }
    Ok(())
}

/// Quantifier starting exactly at `pos`: (`is_unbounded`, bytes consumed).
fn quantifier_at(bytes: &[u8], pos: usize) -> (bool, usize) {
    match bytes.get(pos) {
        Some(b'*') | Some(b'+') => (true, 1),
        Some(b'?') => (false, 1),
        Some(b'{') => brace_quantifier(bytes, pos),
        _ => (false, 0),
    }
}

/// Parse `{n}`, `{n,}`, `{n,m}` at `pos`. `{n,}` is unbounded.
/// Malformed braces are treated as literals (the regex compiler decides).
fn brace_quantifier(bytes: &[u8], pos: usize) -> (bool, usize) {
    debug_assert_eq!(bytes.get(pos), Some(&b'{'));
    let mut j = pos + 1;
    let mut saw_comma_last = false;
    while j < bytes.len() {
        match bytes[j] {
            b'}' => return (saw_comma_last, j - pos + 1),
            b',' => saw_comma_last = true,
            b'0'..=b'9' => saw_comma_last = false,
            _ => return (false, 1), // not a quantifier — literal '{'
        }
        j += 1;
    }
    (false, 1)
}

#[cfg(test)]
mod tests {
    use super::check_nested_repetition;

    #[test]
    fn rejects_nested_unbounded() {
        for p in [
            r"(a+)+",
            r"([a-z]*)*",
            r"(a+)*",
            r"(?:\d+){3,}",
            r"((ab)+c)*",
            r"(x{2,})+",
        ] {
            assert!(
                check_nested_repetition(p).is_err(),
                "{p} should be rejected"
            );
        }
    }

    #[test]
    fn accepts_safe_patterns() {
        for p in [
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", // canonical email rule
            r"(a+)b+",                                         // sibling quantifiers, not nested
            r"(a+){3}",                                        // bounded outer
            r"(a{2,4})+",                                      // bounded inner
            r"(abc)+",                                         // no unbounded inner
            r"\(a+\)+",                                        // escaped parens are literals
            r"[(+*]+",     // metachars inside a class are literals
            r"a{3}\{4,\}", // escaped braces
        ] {
            assert!(check_nested_repetition(p).is_ok(), "{p} should be accepted");
        }
    }
}
