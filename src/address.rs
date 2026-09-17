//! Syntax shared by client-side address selection and range validation.
//! Ghidra remains responsible for checking address spaces and numeric bounds.

#[derive(Debug)]
pub(crate) struct ExplicitAddress<'a> {
    pub space: Option<&'a str>,
    pub components: Vec<&'a str>,
}

impl<'a> ExplicitAddress<'a> {
    pub fn parse(value: &'a str) -> Option<Self> {
        let parts: Vec<_> = value.trim().split(':').collect();
        if Self::valid_components(&parts) {
            return Some(Self {
                space: None,
                components: parts,
            });
        }
        Self::parse_qualified(value)
    }

    /// Canonical output always qualifies segmented addresses, so a colon's
    /// first component is a space name even when it looks hexadecimal.
    pub fn parse_canonical(value: &'a str) -> Option<Self> {
        if value.contains(':') {
            Self::parse_qualified(value)
        } else {
            Self::parse(value)
        }
    }

    fn parse_qualified(value: &'a str) -> Option<Self> {
        let (space, offset) = value.trim().split_once(':')?;
        let components: Vec<_> = offset.split(':').collect();
        if space.is_empty()
            || space.chars().any(|c| c <= ' ')
            || !Self::valid_components(&components)
        {
            return None;
        }
        Some(Self {
            space: Some(space),
            components,
        })
    }

    fn valid_components(components: &[&str]) -> bool {
        if !(1..=2).contains(&components.len()) {
            return false;
        }
        for component in components {
            let Some(digits) = component
                .strip_prefix("0x")
                .or_else(|| component.strip_prefix("0X"))
            else {
                return false;
            };
            let mut fields = digits.split('.');
            let offset = fields.next().unwrap();
            if offset.is_empty() || !offset.bytes().all(|c| c.is_ascii_hexdigit()) {
                return false;
            }
            let Ok(offset) = u64::from_str_radix(offset, 16) else {
                return false;
            };
            if components.len() == 2 && offset > u16::MAX as u64 {
                return false;
            }
            if let Some(remainder) = fields.next() {
                if components.len() != 1
                    || remainder.is_empty()
                    || !remainder.bytes().all(|c| c.is_ascii_hexdigit())
                    || fields.next().is_some()
                {
                    return false;
                }
                if u8::from_str_radix(remainder, 16).map_or(true, |n| n > 7) {
                    return false;
                }
            }
        }
        true
    }

    pub fn same_location(&self, other: &Self) -> bool {
        self.space == other.space
            && self.components.len() == other.components.len()
            && self
                .components
                .iter()
                .zip(&other.components)
                .all(|(left, right)| {
                    fn digits(value: &str) -> (&str, &str) {
                        let value = &value[2..];
                        let (offset, remainder) = value.split_once('.').unwrap_or((value, "0"));
                        (
                            offset.trim_start_matches('0'),
                            remainder.trim_start_matches('0'),
                        )
                    }
                    let (left, left_remainder) = digits(left);
                    let (right, right_remainder) = digits(right);
                    left.eq_ignore_ascii_case(right)
                        && left_remainder.eq_ignore_ascii_case(right_remainder)
                })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_addresses_keep_spaces_segments_and_word_remainders() {
        for valid in [
            "0x10",
            "0XABC",
            "overlay:0x1234",
            "0x1234:0x0005",
            "ram:0x1234:0x5",
            "ram:0x10.1",
            "0xbank:0x10",
            "0x1234:0x1:0x2",
        ] {
            assert!(ExplicitAddress::parse(valid).is_some(), "{valid}");
        }
        for invalid in [
            "10",
            "dead",
            "FUN_00401000",
            "ram:1234",
            "overlay::0x1234",
            "0x1234:5",
            "0x",
            "0x-1",
            "0x1:0x2:0x3:0x4",
            "0x1.2.3",
            "ram:0x1.2:0x3",
            "0x10000000000000000",
            "0x10.8",
        ] {
            assert!(ExplicitAddress::parse(invalid).is_none(), "{invalid}");
        }
        let parse = |value| ExplicitAddress::parse(value).unwrap();
        assert!(parse("ram:0X0010.01").same_location(&parse("ram:0x10.1")));
        assert!(parse("0x10.0").same_location(&parse("0x0010")));
        assert!(!parse("ram:0x10").same_location(&parse("other:0x10")));
        assert!(!parse("0x1234:0x5").same_location(&parse("0x5678:0x5")));
    }

    #[test]
    fn canonical_addresses_preserve_hexadecimal_space_names_verbatim() {
        let parse = |value| ExplicitAddress::parse_canonical(value).unwrap();
        assert!(parse("0xAB:0x0005").same_location(&parse("0xAB:0X5")));
        assert!(!parse("0xAB:0x5").same_location(&parse("0xab:0x5")));
        assert!(!parse("0x1234:0x5").same_location(&parse("0x001234:0x5")));
        assert!(!parse("0x1234:0x5").same_location(&parse("ram:0x1234:0x5")));
    }
}
