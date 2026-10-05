//! Strict UTF-8 JSON with exact integers and bounded nesting.
use crate::{Error, Map, Number, Result, Value};
pub(crate) fn parse(text: &str) -> Result<Value> {
    let mut p = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    let v = p.value(0)?;
    p.ws();
    if p.pos != p.bytes.len() {
        return Err(Error);
    }
    Ok(v)
}
struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }
    fn next(&mut self) -> Result<u8> {
        let b = self.peek().ok_or(Error)?;
        self.pos += 1;
        Ok(b)
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.pos += 1;
        }
    }
    fn expect(&mut self, b: u8) -> Result<()> {
        if self.next()? == b {
            Ok(())
        } else {
            Err(Error)
        }
    }
    fn literal(&mut self, s: &[u8], v: Value) -> Result<Value> {
        for b in s {
            self.expect(*b)?;
        }
        Ok(v)
    }
    fn value(&mut self, depth: usize) -> Result<Value> {
        self.ws();
        match self.peek() {
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'[') => {
                if depth >= 128 {
                    return Err(Error);
                }
                self.pos += 1;
                self.ws();
                let mut a = Vec::new();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(Value::Array(a));
                }
                loop {
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match self.next()? {
                        b']' => break,
                        b',' => {}
                        _ => return Err(Error),
                    }
                }
                Ok(Value::Array(a))
            }
            Some(b'{') => {
                if depth >= 128 {
                    return Err(Error);
                }
                self.pos += 1;
                self.ws();
                let mut m = Map::new();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(Value::Object(m));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    if m.contains_key(&k) {
                        return Err(Error);
                    }
                    self.ws();
                    self.expect(b':')?;
                    let v = self.value(depth + 1)?;
                    m.insert(k, v);
                    self.ws();
                    match self.next()? {
                        b'}' => break,
                        b',' => {}
                        _ => return Err(Error),
                    }
                }
                Ok(Value::Object(m))
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(Error),
        }
    }
    fn hex4(&mut self) -> Result<u32> {
        let mut n = 0;
        for _ in 0..4 {
            let b = self.next()?;
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(Error),
            };
            n = n * 16 + u32::from(d);
        }
        Ok(n)
    }
    fn string(&mut self) -> Result<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        let mut start = self.pos;
        loop {
            let b = self.next()?;
            match b {
                b'"' => {
                    out.push_str(
                        std::str::from_utf8(&self.bytes[start..self.pos - 1]).map_err(|_| Error)?,
                    );
                    return Ok(out);
                }
                b'\\' => {
                    out.push_str(
                        std::str::from_utf8(&self.bytes[start..self.pos - 1]).map_err(|_| Error)?,
                    );
                    let c = match self.next()? {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let high = self.hex4()?;
                            let code = if (0xd800..=0xdbff).contains(&high) {
                                self.expect(b'\\')?;
                                self.expect(b'u')?;
                                let low = self.hex4()?;
                                if !(0xdc00..=0xdfff).contains(&low) {
                                    return Err(Error);
                                }
                                0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00)
                            } else {
                                high
                            };
                            char::from_u32(code).ok_or(Error)?
                        }
                        _ => return Err(Error),
                    };
                    out.push(c);
                    start = self.pos;
                }
                0..=31 => return Err(Error),
                _ => {}
            }
        }
    }
    fn digits(&mut self) -> Result<()> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if start == self.pos {
            Err(Error)
        } else {
            Ok(())
        }
    }
    fn number(&mut self) -> Result<Value> {
        let start = self.pos;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => self.digits()?,
            _ => return Err(Error),
        }
        let mut float = false;
        if self.peek() == Some(b'.') {
            float = true;
            self.pos += 1;
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            self.digits()?;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| Error)?;
        if !float && text != "-0" {
            if negative {
                if let Ok(n) = text.parse::<i64>() {
                    return Ok(Value::Number(n.into()));
                }
            } else if let Ok(n) = text.parse::<u64>() {
                return Ok(Value::Number(n.into()));
            }
        }
        let n = text.parse::<f64>().map_err(|_| Error)?;
        Ok(Value::Number(Number::from_f64(n).ok_or(Error)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_integer_boundaries() {
        assert_eq!(
            parse("18446744073709551615").unwrap().as_u64(),
            Some(u64::MAX)
        );
        assert_eq!(
            parse("-9223372036854775808").unwrap().as_i64(),
            Some(i64::MIN)
        );
        assert_eq!(
            parse("9007199254740993").unwrap().as_u64(),
            Some(9007199254740993)
        );
        assert!(parse("-0").unwrap().is_f64());
    }
    #[test]
    fn strict_syntax_and_decoded_duplicates() {
        for s in [
            "01",
            "-01",
            "1.",
            "1e",
            "+1",
            ".1",
            "1e9999",
            "[1,]",
            "{\"x\":1,}",
            r#"{"a":1,"\u0061":2}"#,
            r#"[ {"x":1,"x":1} ]"#,
            r#""\ud800""#,
            r#""\ud800\u0000""#,
            r#""\udc00""#,
            "true false",
        ] {
            assert!(parse(s).is_err(), "{s}");
        }
        assert_eq!(parse(r#""\ud83d\ude00""#).unwrap().as_str(), Some("😀"));
        assert!(parse(&format!("{}0{}", "[".repeat(129), "]".repeat(129))).is_err());
    }
}
