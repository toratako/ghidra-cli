//! Integer literals shared by CLI value parsers.

pub(crate) trait Integer: TryFrom<i128> {
    const MIN: i128;
    const MAX: i128;
}

macro_rules! integers {
    ($($ty:ty),+ $(,)?) => {
        $(impl Integer for $ty {
            const MIN: i128 = <$ty>::MIN as i128;
            const MAX: i128 = <$ty>::MAX as i128;
        })+
    };
}

integers!(i32, i64, i128, u8, u32, u64, usize);

pub(crate) fn parse<T: Integer>(input: &str) -> Result<T, String> {
    ranged(input, T::MIN, T::MAX)
}

pub(crate) fn ranged<T: Integer>(input: &str, min: i128, max: i128) -> Result<T, String> {
    let min = min.max(T::MIN);
    let max = max.min(T::MAX);
    let range_error = || format!("must be between {min} and {max}");
    let (negative, literal) = match input.as_bytes().first() {
        Some(b'-') => (true, &input[1..]),
        Some(b'+') => (false, &input[1..]),
        _ => (false, input),
    };
    if negative && T::MIN == 0 {
        return Err(range_error());
    }
    let (digits, radix) = literal
        .strip_prefix("0x")
        .or_else(|| literal.strip_prefix("0X"))
        .map_or((literal, 10), |digits| (digits, 16));
    if digits.is_empty()
        || !digits.bytes().all(|digit| match radix {
            16 => digit.is_ascii_hexdigit(),
            _ => digit.is_ascii_digit(),
        })
    {
        return Err("must be a decimal or 0x hexadecimal integer".into());
    }
    let value = if negative {
        i128::from_str_radix(&format!("-{digits}"), radix)
    } else {
        i128::from_str_radix(digits, radix)
    }
    .map_err(|_| range_error())?;
    if value < min || value > max {
        return Err(range_error());
    }
    T::try_from(value).map_err(|_| range_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_hex_and_signs_have_consistent_values() {
        for input in ["10", "010", "+10", "0xa", "0XA", "+0xA"] {
            assert_eq!(parse::<i64>(input), Ok(10), "{input}");
            assert_eq!(parse::<u64>(input), Ok(10), "{input}");
        }
        for input in ["-10", "-010", "-0xa", "-0XA"] {
            assert_eq!(parse::<i64>(input), Ok(-10), "{input}");
            assert!(parse::<u64>(input).is_err(), "{input}");
        }
        assert!(parse::<u8>("-0").is_err());
    }

    #[test]
    fn integer_width_and_signedness_are_enforced() {
        assert_eq!(parse::<i64>("-0x8000000000000000"), Ok(i64::MIN));
        assert_eq!(parse::<i64>("0x7fffffffffffffff"), Ok(i64::MAX));
        assert_eq!(parse::<u64>("0xffffffffffffffff"), Ok(u64::MAX));
        assert_eq!(parse::<i32>("-0x80000000"), Ok(i32::MIN));
        assert_eq!(parse::<u32>("0xffffffff"), Ok(u32::MAX));
        assert_eq!(parse::<u8>("0xff"), Ok(u8::MAX));
        assert_eq!(parse::<usize>(&usize::MAX.to_string()), Ok(usize::MAX));
        assert!(parse::<i64>("0x8000000000000000").is_err());
        assert!(parse::<i64>("-0x8000000000000001").is_err());
        assert!(parse::<u64>("18446744073709551616").is_err());
        assert!(parse::<i32>("0x80000000").is_err());
        assert!(parse::<u8>("0x100").is_err());
        assert!(parse::<u64>("999999999999999999999999999999999999999999").is_err());
    }

    #[test]
    fn full_i128_boundaries_and_mixed_signed_unsigned_ranges_are_supported() {
        assert_eq!(parse::<i128>(&i128::MIN.to_string()), Ok(i128::MIN));
        assert_eq!(
            parse::<i128>("-0x80000000000000000000000000000000"),
            Ok(i128::MIN)
        );
        assert_eq!(
            parse::<i128>("0x7fffffffffffffffffffffffffffffff"),
            Ok(i128::MAX)
        );
        assert!(parse::<i128>("0x80000000000000000000000000000000").is_err());
        assert!(parse::<i128>("-0x80000000000000000000000000000001").is_err());
        assert_eq!(
            ranged::<i128>("0xffffffffffffffff", i64::MIN as i128, u64::MAX as i128),
            Ok(u64::MAX as i128)
        );
        assert_eq!(
            ranged::<i128>("-0x8000000000000000", i64::MIN as i128, u64::MAX as i128),
            Ok(i64::MIN as i128)
        );
        assert!(ranged::<i128>("0x10000000000000000", i64::MIN as i128, u64::MAX as i128).is_err());
    }

    #[test]
    fn ranges_intersect_the_target_type_bounds() {
        assert_eq!(ranged::<u8>("0x10", 1, 16), Ok(16));
        assert!(ranged::<u8>("0", 1, 16).is_err());
        assert!(ranged::<u8>("17", 1, 16).is_err());
        assert!(ranged::<u8>("256", -1000, 1000).is_err());
        assert!(ranged::<i32>("-1", 0, i32::MAX as i128).is_err());
        assert_eq!(
            ranged::<u8>("256", -1000, 1000).unwrap_err(),
            "must be between 0 and 255"
        );
    }

    #[test]
    fn malformed_literals_are_rejected_at_the_shared_boundary() {
        for input in [
            "", "0x", "+", "--1", "+-1", "0x-1", "1.5", "1_000", " 1", "1 ", "１２",
        ] {
            assert!(parse::<i64>(input).is_err(), "{input}");
        }
    }
}
