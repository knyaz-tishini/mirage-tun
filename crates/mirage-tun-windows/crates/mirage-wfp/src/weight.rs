//! Filter weight types.

use std::fmt;

/// Controls filter evaluation order within a sublayer. Higher = first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterWeight {
    /// Let BFE assign a weight automatically (`FWP_EMPTY`).
    Auto,
    /// High 4 bits specified (0–15), low 60 bits auto-generated (`FWP_UINT8`).
    Range(WeightRange),
    /// Exact 64-bit weight (`FWP_UINT64`).
    Exact(u64),
}

/// A weight value in the range 0–15.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WeightRange(u8);

impl WeightRange {
    /// Inner value.
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for WeightRange {
    type Error = WeightRangeError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        if val > 15 {
            Err(WeightRangeError(val))
        } else {
            Ok(Self(val))
        }
    }
}

/// Error when weight range value exceeds 15.
#[derive(Debug, Clone, Copy)]
pub struct WeightRangeError(u8);

impl fmt::Display for WeightRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "weight {} out of range 0..=15", self.0)
    }
}

impl std::error::Error for WeightRangeError {}

impl From<WeightRange> for FilterWeight {
    fn from(r: WeightRange) -> Self {
        FilterWeight::Range(r)
    }
}
