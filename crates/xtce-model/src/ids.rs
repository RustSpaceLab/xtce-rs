//! Typed indices into the [`crate::XtceDb`] arenas.
//!
//! The IR stores every entity in a `Vec` and refers to it by a `u32` newtype rather than by
//! `Rc<RefCell<..>>` or `HashMap<String, ..>`. That keeps the model `Send + Sync`, makes
//! cloning cheap, gives the code generator a stable numbering to emit, and turns reference
//! following into an array index instead of a hash lookup.
//!
//! The newtypes are distinct so that a [`ParamId`] can never be used where a [`ContainerId`]
//! is expected.

use std::fmt;

macro_rules! id_types {
    ($($(#[$meta:meta])* $name:ident),* $(,)?) => {$(
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u32);

        impl $name {
            /// Wraps a raw index.
            #[inline]
            #[must_use]
            pub const fn new(index: u32) -> Self {
                Self(index)
            }

            /// The raw index, for use as an array subscript.
            #[inline]
            #[must_use]
            pub const fn index(self) -> usize {
                self.0 as usize
            }

            /// The raw index as a `u32`, for serialisation and code generation.
            #[inline]
            #[must_use]
            pub const fn raw(self) -> u32 {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }
    )*};
}

id_types! {
    /// Index of a `SpaceSystem`.
    SpaceSystemId,
    /// Index of a `Parameter`.
    ParamId,
    /// Index of a parameter type.
    TypeId,
    /// Index of a `SequenceContainer`.
    ContainerId,
}

/// A contiguous slice of a shared arena, stored in two words.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Span {
    start: u32,
    len: u32,
}

impl Span {
    /// An empty span.
    pub const EMPTY: Self = Self { start: 0, len: 0 };

    /// Builds a span from a start index and length.
    #[inline]
    #[must_use]
    pub const fn new(start: u32, len: u32) -> Self {
        Self { start, len }
    }

    /// Builds a span covering `start..end` of an arena, saturating on overflow.
    #[must_use]
    pub fn between(start: usize, end: usize) -> Self {
        let start_u32 = u32::try_from(start).unwrap_or(u32::MAX);
        let len = u32::try_from(end.saturating_sub(start)).unwrap_or(u32::MAX);
        Self {
            start: start_u32,
            len,
        }
    }

    /// Number of elements covered.
    #[inline]
    #[must_use]
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Whether the span covers nothing.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Slices `arena` with this span, yielding an empty slice if it is out of bounds.
    #[inline]
    #[must_use]
    pub fn slice<T>(self, arena: &[T]) -> &[T] {
        let start = self.start as usize;
        arena
            .get(start..start + self.len as usize)
            .unwrap_or_default()
    }
}
