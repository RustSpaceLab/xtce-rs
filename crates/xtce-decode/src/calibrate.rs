//! Calibrators: raw encoded value to engineering value.

use xtce_model::{Calibrator, PolynomialTerm, Spline};

/// Why a calibrator could not produce a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CalibrationError {
    /// The query point is outside the spline's range and extrapolation is off.
    OutsideSplineRange,
    /// The spline has too few points to interpolate.
    EmptySpline,
    /// The spline order is above 1.
    UnsupportedOrder(u8),
}

impl std::fmt::Display for CalibrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutsideSplineRange => {
                f.write_str("query point falls outside the spline points and extrapolate is false")
            }
            Self::EmptySpline => f.write_str("spline calibrator has no usable points"),
            Self::UnsupportedOrder(order) => {
                write!(f, "spline order {order} is not supported (only 0 and 1)")
            }
        }
    }
}

/// The raw value handed to a calibrator.
///
/// Integers are kept as integers rather than widened to `f64` on the way in, because
/// `coefficient * x.pow(n)` is evaluated exactly for integral `x` where it can be — see
/// [`polynomial`].
#[derive(Clone, Copy, Debug)]
pub enum CalibrationInput {
    /// An integer-encoded raw value.
    Integer(i128),
    /// A float-encoded raw value.
    Float(f64),
}

impl CalibrationInput {
    fn as_f64(self) -> f64 {
        match self {
            Self::Integer(value) => value as f64,
            Self::Float(value) => value,
        }
    }
}

/// Applies a calibrator.
///
/// # Errors
///
/// Returns [`CalibrationError`] for a spline query that cannot be answered. Polynomials
/// never fail.
pub fn apply(calibrator: &Calibrator, input: CalibrationInput) -> Result<f64, CalibrationError> {
    match calibrator {
        Calibrator::Polynomial(terms) => Ok(polynomial(terms, input)),
        Calibrator::Spline(spline) => interpolate(spline, input.as_f64()),
        // Reaching an unsupported calibrator is a caller error; it is filtered out before
        // this point so that the failure carries the parameter's name.
        Calibrator::Unsupported { .. } => Ok(input.as_f64()),
    }
}

/// Evaluates a polynomial calibrator.
///
/// Terms are summed in document order, not Horner's method and not sorted by exponent.
/// Floating-point addition is neither associative nor commutative, so any reordering shifts
/// the low bits of the result — and correctness here is defined by bit-for-bit agreement
/// with a reference implementation that sums in document order.
///
/// For an integral raw value and a non-negative exponent the power is computed in `i128` and
/// converted once, which is exactly what the Python reference does with its arbitrary-
/// precision integers. Repeated `f64` multiplication would round at every step and drift for
/// large values.
#[must_use]
pub fn polynomial(terms: &[PolynomialTerm], input: CalibrationInput) -> f64 {
    let mut sum = 0.0f64;
    for term in terms {
        sum += term.coefficient * power(input, term.exponent);
    }
    sum
}

fn power(input: CalibrationInput, exponent: i32) -> f64 {
    match input {
        CalibrationInput::Integer(base) if exponent >= 0 => {
            match u32::try_from(exponent)
                .ok()
                .and_then(|exponent| base.checked_pow(exponent))
            {
                Some(exact) => exact as f64,
                // Overflowed `i128`; no exact route left, so fall back to floating point.
                None => (base as f64).powi(exponent),
            }
        }
        CalibrationInput::Integer(base) => (base as f64).powi(exponent),
        CalibrationInput::Float(base) => base.powi(exponent),
    }
}

/// Evaluates a spline calibrator at `query`.
///
/// # Errors
///
/// Returns [`CalibrationError`] when the query is out of range with extrapolation disabled,
/// when the spline has no usable points, or for orders above 1.
pub fn interpolate(spline: &Spline, query: f64) -> Result<f64, CalibrationError> {
    let points = spline.points.as_slice();
    let (Some(first), Some(last)) = (points.first(), points.last()) else {
        return Err(CalibrationError::EmptySpline);
    };

    if query < first.raw {
        if !spline.extrapolate {
            return Err(CalibrationError::OutsideSplineRange);
        }
        return match spline.order {
            0 => Ok(first.calibrated),
            1 => match points.get(1) {
                Some(second) => Ok(line(
                    query,
                    first.raw,
                    second.raw,
                    first.calibrated,
                    second.calibrated,
                )),
                None => Ok(first.calibrated),
            },
            other => Err(CalibrationError::UnsupportedOrder(other)),
        };
    }

    if query > last.raw {
        if !spline.extrapolate {
            return Err(CalibrationError::OutsideSplineRange);
        }
        return match spline.order {
            0 => Ok(last.calibrated),
            1 => match points.len().checked_sub(2).and_then(|i| points.get(i)) {
                Some(prev) => Ok(line(
                    query,
                    prev.raw,
                    last.raw,
                    prev.calibrated,
                    last.calibrated,
                )),
                None => Ok(last.calibrated),
            },
            other => Err(CalibrationError::UnsupportedOrder(other)),
        };
    }

    // In range. `partition_point` gives the index of the first point strictly above the
    // query, so the enclosing segment is `[index - 1, index]`.
    //
    // The reference implementation raises here when the query equals the largest raw value,
    // because its `list.index(True)` finds no element greater than the query. That is a bug,
    // not a specification: XTCE says the range is inclusive. This clamps to the final
    // segment instead, which is recorded as a deliberate divergence in `SUPPORTED.md`.
    // `hi` is the index of the first point strictly above the query. It is at least 1
    // because `query >= first.raw` was established above — except for a NaN query, where
    // every comparison is false, so it is floored explicitly.
    let hi = points.partition_point(|point| point.raw <= query).max(1);

    match spline.order {
        // Nearest lower point: the last point at or below the query, which for a query
        // sitting exactly on a point is that point itself.
        0 => Ok(points
            .get(hi - 1)
            .map_or(first.calibrated, |point| point.calibrated)),
        1 => {
            if points.len() < 2 {
                return Ok(first.calibrated);
            }
            // A query equal to the last raw value has no point above it; interpolating over
            // the final segment evaluates to exactly that point's calibrated value.
            let upper = hi.min(points.len() - 1);
            let (Some(lower_point), Some(upper_point)) = (points.get(upper - 1), points.get(upper))
            else {
                return Ok(first.calibrated);
            };
            Ok(line(
                query,
                lower_point.raw,
                upper_point.raw,
                lower_point.calibrated,
                upper_point.calibrated,
            ))
        }
        other => Err(CalibrationError::UnsupportedOrder(other)),
    }
}

/// The line through `(x0, y0)` and `(x1, y1)`, evaluated at `x`.
fn line(x: f64, x0: f64, x1: f64, y0: f64, y1: f64) -> f64 {
    if (x1 - x0) == 0.0 {
        return y0;
    }
    let slope = (y1 - y0) / (x1 - x0);
    slope * (x - x0) + y0
}

#[cfg(test)]
mod tests {
    use super::*;
    use xtce_model::SplinePoint;

    fn spline(order: u8, extrapolate: bool, points: &[(f64, f64)]) -> Spline {
        Spline {
            order,
            points: points
                .iter()
                .map(|&(raw, calibrated)| SplinePoint { raw, calibrated })
                .collect(),
            extrapolate,
        }
    }

    #[test]
    fn polynomial_sums_in_document_order() {
        let terms = [
            PolynomialTerm {
                coefficient: 1.0,
                exponent: 0,
            },
            PolynomialTerm {
                coefficient: 2.0,
                exponent: 1,
            },
            PolynomialTerm {
                coefficient: 3.0,
                exponent: 2,
            },
        ];
        assert_eq!(polynomial(&terms, CalibrationInput::Integer(2)), 17.0);
        assert_eq!(polynomial(&terms, CalibrationInput::Float(2.0)), 17.0);
        assert_eq!(polynomial(&[], CalibrationInput::Integer(9)), 0.0);
    }

    #[test]
    fn integer_powers_stay_exact_beyond_the_f64_mantissa() {
        // 2^27 squared is 2^54, one bit past the exact-integer range of f64. Computing it
        // exactly and rounding once gives a different answer from rounding twice would.
        let base: i128 = (1 << 27) + 1;
        let terms = [PolynomialTerm {
            coefficient: 1.0,
            exponent: 2,
        }];
        let exact = (base * base) as f64;
        assert_eq!(polynomial(&terms, CalibrationInput::Integer(base)), exact);
    }

    #[test]
    fn zero_order_spline_takes_the_nearest_lower_point() {
        let spline = spline(0, false, &[(0.0, 10.0), (10.0, 20.0), (20.0, 30.0)]);
        assert_eq!(interpolate(&spline, 0.0), Ok(10.0));
        assert_eq!(interpolate(&spline, 9.9), Ok(10.0));
        assert_eq!(interpolate(&spline, 10.0), Ok(20.0));
        assert_eq!(interpolate(&spline, 19.0), Ok(20.0));
        // Upper bound is inclusive here, where the reference raises.
        assert_eq!(interpolate(&spline, 20.0), Ok(30.0));
    }

    #[test]
    fn first_order_spline_interpolates() {
        let spline = spline(1, false, &[(0.0, 0.0), (10.0, 100.0)]);
        assert_eq!(interpolate(&spline, 0.0), Ok(0.0));
        assert_eq!(interpolate(&spline, 5.0), Ok(50.0));
        assert_eq!(interpolate(&spline, 10.0), Ok(100.0));
    }

    #[test]
    fn out_of_range_respects_extrapolate() {
        let bounded = spline(1, false, &[(0.0, 0.0), (10.0, 100.0)]);
        assert_eq!(
            interpolate(&bounded, -1.0),
            Err(CalibrationError::OutsideSplineRange)
        );
        assert_eq!(
            interpolate(&bounded, 11.0),
            Err(CalibrationError::OutsideSplineRange)
        );

        let unbounded = spline(1, true, &[(0.0, 0.0), (10.0, 100.0)]);
        assert_eq!(interpolate(&unbounded, -1.0), Ok(-10.0));
        assert_eq!(interpolate(&unbounded, 11.0), Ok(110.0));

        let flat = spline(0, true, &[(0.0, 7.0), (10.0, 9.0)]);
        assert_eq!(interpolate(&flat, -5.0), Ok(7.0));
        assert_eq!(interpolate(&flat, 50.0), Ok(9.0));
    }

    #[test]
    fn degenerate_splines_do_not_panic() {
        assert_eq!(
            interpolate(&spline(1, true, &[]), 1.0),
            Err(CalibrationError::EmptySpline)
        );
        let single = spline(1, true, &[(5.0, 42.0)]);
        assert_eq!(interpolate(&single, 5.0), Ok(42.0));
        assert_eq!(interpolate(&single, 1.0), Ok(42.0));
        assert_eq!(interpolate(&single, 9.0), Ok(42.0));
        assert_eq!(
            interpolate(&spline(2, true, &[(0.0, 0.0), (1.0, 1.0)]), 0.5),
            Err(CalibrationError::UnsupportedOrder(2))
        );
    }
}
