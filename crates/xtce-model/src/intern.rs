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
/// cost one amortised allocation rather than `N`.
///
/// # Why not `HashMap<Box<str>, NameId>`
///
/// The obvious implementation allocates a `Box<str>` for every unique name and stores the
/// text twice. Loading the 1.6 MB CTIM database interns about nineteen thousand names, so
/// that is nineteen thousand allocations and a few hundred kilobytes of duplication on a
/// path whose whole purpose is to be fast.
///
/// This is an open-addressing table whose entries are `NameId`s. A probe compares against
/// the text already in the arena, so nothing is stored twice and a hash collision resolves
/// correctly rather than merging two distinct names — which is the failure mode of the
/// tempting "just key the map on the hash" shortcut.
#[derive(Default)]
pub struct Interner {
    blob: String,
    spans: Vec<(u32, u32)>,
    /// `id + 1` for an occupied bucket, `0` for an empty one. Length is a power of two.
    buckets: Vec<u32>,
}

/// Grow when the table is this full, as a fraction of capacity: `len * 8 >= capacity * 5`.
///
/// Linear probing degrades sharply as the table fills, and the names in a mission database
/// are anything but random — CTIM's are nine thousand variations on `CTIM__XACT_`.
const LOAD_NUMERATOR: usize = 5;
const LOAD_DENOMINATOR: usize = 8;

impl Interner {
    /// Creates an interner with capacity for roughly `names` entries and `bytes` of text.
    #[must_use]
    pub fn with_capacity(names: usize, bytes: usize) -> Self {
        let mut interner = Self {
            blob: String::with_capacity(bytes),
            spans: Vec::with_capacity(names),
            buckets: Vec::new(),
        };
        interner.resize_buckets(names.saturating_mul(2).max(16).next_power_of_two());
        interner
    }

    /// Interns `s`, returning its handle. Repeated calls with equal strings return the
    /// same handle, and nothing is allocated per name.
    pub fn intern(&mut self, s: &str) -> NameId {
        if self.buckets.is_empty() {
            self.resize_buckets(16);
        }
        if self.spans.len() * LOAD_DENOMINATOR >= self.buckets.len() * LOAD_NUMERATOR {
            self.resize_buckets(self.buckets.len() * 2);
        }

        let hash = hash_str(s);
        let mask = self.buckets.len() - 1;
        let mut index = (hash as usize) & mask;
        loop {
            match self.buckets.get(index).copied() {
                None | Some(0) => break,
                Some(slot) => {
                    let id = NameId(slot - 1);
                    if self.resolve(id) == s {
                        return id;
                    }
                    index = (index + 1) & mask;
                }
            }
        }

        let start = u32::try_from(self.blob.len()).unwrap_or(u32::MAX);
        let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
        self.blob.push_str(s);
        let id = NameId(u32::try_from(self.spans.len()).unwrap_or(u32::MAX));
        self.spans.push((start, len));
        if let Some(slot) = self.buckets.get_mut(index) {
            *slot = id.0 + 1;
        }
        id
    }

    /// Returns the handle for `s` if it has been interned, without interning it.
    #[must_use]
    pub fn get(&self, s: &str) -> Option<NameId> {
        if self.buckets.is_empty() {
            return None;
        }
        let hash = hash_str(s);
        let mask = self.buckets.len() - 1;
        let mut index = (hash as usize) & mask;
        loop {
            match self.buckets.get(index).copied() {
                None | Some(0) => return None,
                Some(slot) => {
                    let id = NameId(slot - 1);
                    if self.resolve(id) == s {
                        return Some(id);
                    }
                    index = (index + 1) & mask;
                }
            }
        }
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

    /// Rebuilds the bucket table at `capacity`, which must be a power of two.
    fn resize_buckets(&mut self, capacity: usize) {
        let capacity = capacity.max(16).next_power_of_two();
        let mut buckets = vec![0u32; capacity];
        let mask = capacity - 1;
        for (index, &(start, len)) in self.spans.iter().enumerate() {
            let (from, to) = (start as usize, start as usize + len as usize);
            let text = self.blob.get(from..to).unwrap_or_default();
            let mut slot = (hash_str(text) as usize) & mask;
            while buckets.get(slot).copied().unwrap_or(0) != 0 {
                slot = (slot + 1) & mask;
            }
            if let Some(bucket) = buckets.get_mut(slot) {
                *bucket = u32::try_from(index).unwrap_or(u32::MAX) + 1;
            }
        }
        self.buckets = buckets;
    }
}

fn hash_str(s: &str) -> u64 {
    let mut hasher = FxHasher::default();
    hasher.write(s.as_bytes());
    mix(hasher.finish())
}

/// The `splitmix64` finalizer.
///
/// [`FxHasher`] is fast but its low bits carry little entropy, and a bucket index is exactly
/// the low bits. XTCE names share long prefixes — every parameter in the CTIM database
/// starts `CTIM__` — so without this the table clusters badly enough to cost more than the
/// allocations it was meant to save. Measured on that file: 16.5 ms without, 9.4 ms with.
#[inline]
const fn mix(mut hash: u64) -> u64 {
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    hash ^ (hash >> 33)
}

impl fmt::Debug for Interner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Interner")
            .field("names", &self.spans.len())
            .field("bytes", &self.blob.len())
            // The blob is megabytes of XTCE identifiers; summarising is the only useful
            // thing to print.
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
    fn survives_growth_with_adversarial_names() {
        // Long shared prefixes are the realistic worst case for a hand-rolled table: every
        // parameter in a mission database looks like its neighbours. This also forces
        // several rehashes, which is where an off-by-one in the resize would show up.
        let mut interner = Interner::with_capacity(4, 16);
        let names: Vec<String> = (0..5_000)
            .map(|index| format!("CTIM__XACT_SUBSYSTEM_CHANNEL_{index:05}"))
            .collect();

        let ids: Vec<NameId> = names.iter().map(|name| interner.intern(name)).collect();
        assert_eq!(interner.len(), names.len());

        for (name, id) in names.iter().zip(&ids) {
            assert_eq!(interner.resolve(*id), name.as_str());
            assert_eq!(interner.get(name), Some(*id));
            assert_eq!(interner.intern(name), *id);
        }
        assert_eq!(
            interner.len(),
            names.len(),
            "re-interning must not add entries"
        );

        // Every handle must be distinct.
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());

        assert_eq!(interner.get("CTIM__XACT_SUBSYSTEM_CHANNEL_99999"), None);
    }

    #[test]
    fn distinguishes_names_that_differ_only_at_the_end() {
        let mut interner = Interner::default();
        let a = interner.intern("PARAM_0000000000000001");
        let b = interner.intern("PARAM_0000000000000002");
        assert_ne!(a, b);
        assert_eq!(interner.resolve(a), "PARAM_0000000000000001");
        assert_eq!(interner.resolve(b), "PARAM_0000000000000002");
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
