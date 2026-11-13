use zeroize::Zeroizing;

/// Text that holds secrets and grows by moving to a bigger buffer, wiping the old one, so a
/// reallocation never leaves a copy behind in freed memory.
pub struct WipedString(Zeroizing<String>);

impl WipedString {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(String::with_capacity(capacity)))
    }

    pub fn push(&mut self, c: char) {
        self.room(c.len_utf8());
        self.0.push(c);
    }

    pub fn push_str(&mut self, text: &str) {
        self.room(text.len());
        self.0.push_str(text);
    }

    fn room(&mut self, more: usize) {
        if self.0.capacity() - self.0.len() >= more {
            return;
        }
        let mut bigger = Zeroizing::new(String::with_capacity(grown(&self.0, more)));
        bigger.push_str(&self.0);
        self.0 = bigger;
    }

    pub fn into_inner(self) -> Zeroizing<String> {
        self.0
    }
}

impl std::ops::Deref for WipedString {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Write for WipedString {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        self.push_str(text);
        Ok(())
    }
}

/// `WipedString` for bytes.
#[derive(Clone)]
pub struct WipedBytes(Zeroizing<Vec<u8>>);

impl WipedBytes {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    pub fn push(&mut self, byte: u8) {
        self.room(1);
        self.0.push(byte);
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.room(bytes.len());
        self.0.extend_from_slice(bytes);
    }

    fn room(&mut self, more: usize) {
        if self.0.capacity() - self.0.len() >= more {
            return;
        }
        let mut bigger = Zeroizing::new(Vec::with_capacity(grown(&self.0, more)));
        bigger.extend_from_slice(&self.0);
        self.0 = bigger;
    }

    pub fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl std::ops::Deref for WipedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::DerefMut for WipedBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl std::io::Write for WipedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn grown(now: &impl AsRef<[u8]>, more: usize) -> usize {
    let len = now.as_ref().len();
    (len + more).max(len * 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_grows_past_its_first_buffer_and_keeps_every_byte() {
        let mut text = WipedString::with_capacity(2);
        for part in ["ab", "c", "défg", "", "h"] {
            text.push_str(part);
        }
        text.push('é');
        std::fmt::Write::write_fmt(&mut text, format_args!("{}", 42)).unwrap();
        assert_eq!(&*text, "abcdéfghé42");
    }

    #[test]
    fn bytes_grow_past_their_first_buffer_and_keep_every_byte() {
        let mut bytes = WipedBytes::with_capacity(1);
        bytes.extend_from_slice(b"ab");
        for b in b"cdefghij" {
            bytes.push(*b);
        }
        assert_eq!(&*bytes, b"abcdefghij");
        assert_eq!(&**bytes.into_inner(), b"abcdefghij");
    }
}
