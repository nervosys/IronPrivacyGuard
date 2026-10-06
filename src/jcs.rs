//! JSON Canonicalization Scheme (RFC 8785).
//!
//! Produces the UTF-8 bytes signed for structured data: no whitespace, object
//! members sorted by UTF-16 code units, ECMAScript number serialization and
//! JSON.stringify string escaping. Input must be I-JSON (RFC 7493): duplicate
//! names are already refused by IPG's parser, and integers outside ±2^53 are
//! refused here because their double rounding would let two different
//! documents share one canonical form.
use crate::error::{Error, Result};
use ipg_json::{Number, Value};
use std::fmt::Write;

const MAX_SAFE: u64 = 1 << 53;

fn invalid(message: &str) -> Error {
    Error::new("invalid_format", message)
}

/// Parse JSON that will be canonicalized. Integer literals that do not fit
/// 64 bits are refused: the general decoder reads them as doubles, so two
/// different integers could otherwise share one canonical form.
pub fn parse(document: &[u8]) -> Result<Value> {
    let (mut in_string, mut escaped, mut i) = (false, false, 0);
    while i < document.len() {
        let b = document[i];
        if in_string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            i += 1;
        } else if b == b'"' {
            in_string = true;
            i += 1;
        } else if b == b'-' || b.is_ascii_digit() {
            let start = i;
            while i < document.len()
                && matches!(document[i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
            {
                i += 1;
            }
            let token = std::str::from_utf8(&document[start..i]).unwrap_or("");
            let integral = !token.contains(['.', 'e', 'E']);
            if integral && token.parse::<i64>().is_err() && token.parse::<u64>().is_err() {
                return Err(invalid(
                    "Integer literals beyond 64 bits cannot be canonicalized exactly (I-JSON)",
                ));
            }
        } else {
            i += 1;
        }
    }
    ipg_json::from_slice(document).map_err(|_| invalid("Input is not strict I-JSON"))
}

/// Canonical UTF-8 bytes of a JSON value.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Ok(out.into_bytes())
}

fn write_value(out: &mut String, value: &Value) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number(*n)?),
        Value::String(s) => string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (name, item)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(out, name);
                out.push(':');
                write_value(out, item)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// ECMAScript Number::toString for a finite double (ECMA-262 7.1.12.1).
fn number(n: Number) -> Result<String> {
    let value = match n {
        // Compared as integers: 2^53 + 1 rounds to 2^53 as a double.
        Number::Unsigned(v) if v > MAX_SAFE => None,
        Number::Signed(v) if v.unsigned_abs() > MAX_SAFE => None,
        _ => n.as_f64(),
    }
    .ok_or_else(|| invalid("Integers beyond ±2^53 cannot be canonicalized exactly (I-JSON)"))?;
    if !value.is_finite() {
        return Err(invalid("Non-finite numbers cannot be canonicalized"));
    }
    if value == 0.0 {
        return Ok("0".into());
    }
    // Shortest round-trip digit count, then the closest decimal with that many
    // digits (exact rounding, ties to even), as ECMA-262 Note 2 prefers.
    let shortest = format!("{:e}", value.abs());
    let precision = shortest
        .split_once('e')
        .map_or(0, |(m, _)| m.len().saturating_sub(2));
    let closest = format!("{:.*e}", precision, value.abs());
    let scientific = if closest.parse::<f64>() == Ok(value.abs()) {
        closest
    } else {
        shortest
    };
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("LowerExp always has an exponent");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exponent.parse::<i32>().expect("decimal exponent") + 1;
    let mut out = String::new();
    if value < 0.0 {
        out.push('-');
    }
    if k <= n && n <= 21 {
        out.push_str(&digits);
        out.extend(std::iter::repeat_n('0', (n - k) as usize));
    } else if 0 < n && n <= 21 {
        out.push_str(&digits[..n as usize]);
        out.push('.');
        out.push_str(&digits[n as usize..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        out.extend(std::iter::repeat_n('0', (-n) as usize));
        out.push_str(&digits);
    } else {
        out.push_str(&digits[..1]);
        if k > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let _ = write!(
            out,
            "e{}{}",
            if n - 1 < 0 { '-' } else { '+' },
            (n - 1).abs()
        );
    }
    Ok(out)
}

/// JSON.stringify string escaping.
fn string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8785_number_serialization_samples() {
        for (bits, expected) in [
            (0x0000000000000000u64, "0"),
            (0x8000000000000000, "0"),
            (0x0000000000000001, "5e-324"),
            (0x8000000000000001, "-5e-324"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
            (0xffefffffffffffff, "-1.7976931348623157e+308"),
            (0x4340000000000000, "9007199254740992"),
            (0xc340000000000000, "-9007199254740992"),
            (0x4430000000000000, "295147905179352830000"),
            (0x44b52d02c7e14af5, "9.999999999999997e+22"),
            (0x44b52d02c7e14af6, "1e+23"),
            (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
            (0x444b1ae4d6e2ef4e, "999999999999999700000"),
            (0x444b1ae4d6e2ef4f, "999999999999999900000"),
            (0x444b1ae4d6e2ef50, "1e+21"),
            (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
            (0x3eb0c6f7a0b5ed8d, "0.000001"),
            (0x41b3de4355555553, "333333333.3333332"),
            (0x41b3de4355555554, "333333333.33333325"),
            (0x41b3de4355555555, "333333333.3333333"),
            (0x41b3de4355555556, "333333333.3333334"),
            (0x41b3de4355555557, "333333333.33333343"),
            (0xbecbf647612f3696, "-0.0000033333333333333333"),
            (0x43143ff3c1cb0959, "1424953923781206.2"),
        ] {
            let value = Number::Float(f64::from_bits(bits));
            assert_eq!(number(value).unwrap(), expected, "{bits:016x}");
        }
        assert_eq!(
            number(Number::Unsigned(9_007_199_254_740_992)).unwrap(),
            "9007199254740992"
        );
        assert!(number(Number::Unsigned(9_007_199_254_740_993)).is_err());
        assert!(number(Number::Signed(-9_007_199_254_740_993)).is_err());
        assert_eq!(number(Number::Signed(-42)).unwrap(), "-42");
    }

    /// A JSON escape built at runtime, so this source holds no literal escapes.
    fn esc(code: &str) -> String {
        format!("{}u{code}", '\\')
    }

    #[test]
    fn rfc8785_primitive_and_sorting_samples() {
        let b = '\\';
        let string = format!(
            "{}${}{}A'{}{}{}{b}{b}{b}\"{b}/",
            esc("20ac"),
            esc("000F"),
            esc("000a"),
            esc("0042"),
            esc("0022"),
            esc("005c"),
        );
        let sample = format!(
            "{{\"numbers\": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], \"string\": \"{string}\", \"literals\": [null, true, false]}}"
        );
        let value: Value = ipg_json::from_str(&sample).unwrap();
        // RFC 8785 section 3.2.4: the exact canonical UTF-8 bytes.
        let expected = crate::hex::decode(concat!(
            "7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c226e756d62657273223a",
            "5b3333333333333333332e333333333333332c31652b33302c342e352c302e3030322c31652d3237",
            "5d2c22737472696e67223a22e282ac245c75303030665c6e4127425c225c5c5c5c5c222f227d"
        ))
        .unwrap();
        assert_eq!(canonicalize(&value).unwrap(), expected);

        let keys = [
            (esc("20ac"), "Euro Sign"),
            (format!("{b}r"), "Carriage Return"),
            (esc("fb33"), "Hebrew Letter Dalet With Dagesh"),
            ("1".to_string(), "One"),
            (
                format!("{}{}", esc("d83d"), esc("de00")),
                "Emoji: Grinning Face",
            ),
            (esc("0080"), "Control"),
            (esc("00f6"), "Latin Small Letter O With Diaeresis"),
        ];
        let members: Vec<String> = keys
            .iter()
            .map(|(k, v)| format!("\"{k}\":\"{v}\""))
            .collect();
        let value: Value = ipg_json::from_str(&format!("{{{}}}", members.join(","))).unwrap();
        let canonical = String::from_utf8(canonicalize(&value).unwrap()).unwrap();
        let order = [
            "Carriage Return",
            "One",
            "Control",
            "Latin Small Letter O With Diaeresis",
            "Euro Sign",
            "Emoji: Grinning Face",
            "Hebrew Letter Dalet With Dagesh",
        ];
        let positions: Vec<usize> = order.iter().map(|v| canonical.find(v).unwrap()).collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{canonical}");
    }
}
