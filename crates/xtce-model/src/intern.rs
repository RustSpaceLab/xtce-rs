//! String interning.
//!
//! XTCE documents repeat the same identifiers many times: a parameter name appears in
//! `<Parameter>`, in every `<ParameterRefEntry>` that references it, and in every
//! `<Comparison>` that tests it. Interning collapses those to a single `u32`, which keeps
//! the IR small, makes equality a register compare, and lets the decoder key lookups on an
//! integer instead of a string.

use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasherDefault, Hasher};

/// A handle to an interned string.
///
/// Equality on `NameId` is exactly string equality for strings from the same [`Interner`],
/// because interning is canonical.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NameId(u32);

impl NameId {
    /// The first handle any interner hands out. Useful as a placeholder; it resolves to
    /// whatever string was interned first, so never rely on its text.
    pub const ZERO: Self = Self(0);

    /// The numeric index, for use as a dense array key.
    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Debug for NameId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NameId({})", self.0)
    }
}

/// An append-only string arena that hands out [`NameId`]s.
///
/// Strings are concatenated into one `String` and addressed by `(start, len)`, so `N` names
/// cost one allocation amortised rather than `N`.
#[derive(Default)]
pub struct Interner {
    blob: String,
    spans: Vec<(u32, u32)>,
    lookup: HashMap<Box<str>, NameId, BuildHasherDefault<FxHasher>>,
}

impl Interner {
    /// Creates an interner with capacity for roughly `names` entries and `bytes` of text.
    #[must_use]
    pub fn with_capacity(names: usize, bytes: usize) -> Self {
        Self {
            blob: String::with_capacity(bytes),
            spans: Vec::with_capacity(names),
            lookup: HashMap::with_capacity_and_hasher(names, BuildHasherDefault::default()),
        }
    }

    /// Interns `s`, returning its handle. Repeated calls with equal strings return the
    /// same handle and do not allocate.
    pub fn intern(&mut self, s: &str) -> NameId {
        if let Some(&id) = self.lookup.get(s) {
            return id;
        }
        let start = u32::try_from(self.blob.len()).unwrap_or(u32::MAX);
        let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
        self.blob.push_str(s);
        let id = NameId(u32::try_from(self.spans.len()).unwrap_or(u32::MAX));
        self.spans.push((start, len));
        self.lookup.insert(s.into(), id);
        id
    }

    /// Returns the handle for `s` if it has been interned, without interning it.
    #[must_use]
    pub fn get(&self, s: &str) -> Option<NameId> {
        self.lookup.get(s).copied()
    }

    /// Resolves a handle back to its string.
    ///
    /// Returns `""` for a handle minted by a different interner, which cannot happen for
    /// handles obtained through the public API of a single [`crate::XtceDb`].
    #[must_use]
    pub fn resolve(&self, id: NameId) -> &str {
        match self.spans.get(id.index()) {
            Some(&(start, len)) => {
                let (start, end) = (start as usize, start as usize + len as usize);
                self.blob.get(start..end).unwrap_or_default()
            }
            None => "",
        }
    }

    /// Number of distinct interned strings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spans.len()
    }

    /// Whether nothing has been interned yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// Total bytes of unique string data held.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.blob.len()
    }
}

impl fmt::Debug for Interner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Interner")
            .field("names", &self.spans.len())
            .field("bytes", &self.blob.len())
            // The blob and lookup table are megabytes of XTCE identifiers; summarising is
            // the only useful thing to print.
            .finish_non_exhaustive()
    }
}

/// The hash used by `rustc` itself: a multiply-xor-rotate mixer.
///
/// `SipHash` costs roughly 1 ns per short key and interning is the hottest loop in loading,
/// so the default hasher measurably dominates parse time. These keys are XTCE identifiers
/// from a file the caller chose to load, not adversarial input, so `HashDoS` resistance buys
/// nothing here.
#[derive(Default)]
pub struct FxHasher {
    hash: u64,
}

impl FxHasher {
    const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

    #[inline]
    fn add(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(Self::SEED);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            // `chunks_exact(8)` guarantees the length, so the conversion cannot fail.
            let word = u64::from_ne_bytes(chunk.try_into().unwrap_or([0; 8]));
            self.add(word);
        }
        let rest = chunks.remainder();
        if !rest.is_empty() {
            let mut buf = [0u8; 8];
            if let Some(slot) = buf.get_mut(..rest.len()) {
                slot.copy_from_slice(rest);
            }
            self.add(u64::from_ne_bytes(buf));
        }
        // Mix the length so that "ab" and "ab\0" differ.
        self.add(bytes.len() as u64);
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add(u64::from(i));
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add(u64::from(i));
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
}

/// A `HashMap` using [`FxHasher`].
pub type FxHashMap<K, V> = HashMap<K, V, BuildHasherDefault<FxHasher>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interning_is_canonical() {
        let mut interner = Interner::default();
        let a = interner.intern("PKT_APID");
        let b = interner.intern("VERSION");
        let c = interner.intern("PKT_APID");
        assert_eq!(a, c);
        assert_ne!(a, b);
        assert_eq!(interner.len(), 2);
        assert_eq!(interner.resolve(a), "PKT_APID");
        assert_eq!(interner.resolve(b), "VERSION");
    }

    #[test]
    fn get_does_not_intern() {
        let mut interner = Interner::default();
        assert_eq!(interner.get("nope"), None);
        let id = interner.intern("nope");
        assert_eq!(interner.get("nope"), Some(id));
        assert_eq!(interner.len(), 1);
    }

    #[test]
    fn empty_string_round_trips() {
        let mut interner = Interner::default();
        let id = interner.intern("");
        assert_eq!(interner.resolve(id), "");
        assert_eq!(interner.intern(""), id);
    }

    #[test]
    fn resolve_rejects_foreign_handle() {
        let mut a = Interner::default();
        let id = a.intern("x");
        let b = Interner::default();
        assert_eq!(b.resolve(id), "");
    }

    #[test]
    fn hashing_distinguishes_length() {
        use std::hash::Hash;
        let hash_of = |s: &str| {
            let mut h = FxHasher::default();
            s.hash(&mut h);
            h.finish()
        };
        assert_ne!(hash_of("ab"), hash_of("ab\0"));
        assert_eq!(hash_of("abcdefghij"), hash_of("abcdefghij"));
    }
}
