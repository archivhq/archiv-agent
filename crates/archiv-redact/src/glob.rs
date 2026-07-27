//! Minimal `*`-wildcard glob over attribute key bytes (`core/04` §3:
//! `fields: [body, "attributes.*"]`). Only `*` is special (matches any run of
//! bytes, including empty); everything else is a literal byte. No allocation.

/// Iterative two-pointer wildcard match — O(len(key) · stars), no recursion.
pub(crate) fn matches(pattern: &[u8], key: &[u8]) -> bool {
    let (mut p, mut k) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None; // (pattern idx after '*', key idx)

    while k < key.len() {
        if p < pattern.len() && (pattern[p] == key[k]) {
            p += 1;
            k += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p + 1, k));
            p += 1;
        } else if let Some((sp, sk)) = star {
            // Backtrack: let the last '*' absorb one more byte.
            p = sp;
            k = sk + 1;
            star = Some((sp, sk + 1));
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn glob_semantics() {
        assert!(matches(b"*", b"anything"));
        assert!(matches(b"*", b""));
        assert!(matches(b"user.*", b"user.email"));
        assert!(matches(b"user.*", b"user."));
        assert!(!matches(b"user.*", b"username")); // '.' is literal
        assert!(matches(b"*.email", b"user.email"));
        assert!(matches(b"u*r.*l", b"user.email")); // multi-star backtracking
        assert!(matches(b"exact", b"exact"));
        assert!(!matches(b"exact", b"exact-no"));
        assert!(!matches(b"", b"x"));
        assert!(matches(b"", b""));
    }
}
