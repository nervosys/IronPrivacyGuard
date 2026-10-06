//! Secret ownership with erasure delegated to IronCrypto's volatile wipe.
use std::ops::{Deref, DerefMut};

pub trait Zeroize {
    fn zeroize(&mut self);
}
macro_rules! arrays {
    ($($word:ty),*) => {$ (
        impl<const N: usize> Zeroize for [$word; N] {
            fn zeroize(&mut self) { ic_core::Zeroize::zeroize(self); }
        }
    )*};
}
arrays!(u8, u32, u64);
impl Zeroize for Vec<u8> {
    fn zeroize(&mut self) {
        // Cover initialized and spare capacity without allocating another buffer.
        self.resize(self.capacity(), 0);
        ic_core::Zeroize::zeroize(self.as_mut_slice());
        self.clear();
    }
}
impl Zeroize for Vec<u32> {
    fn zeroize(&mut self) {
        self.resize(self.capacity(), 0);
        ic_core::Zeroize::zeroize(self.as_mut_slice());
        self.clear();
    }
}
impl Zeroize for String {
    fn zeroize(&mut self) {
        // into_bytes transfers the allocation; no UTF-8 mutation or unsafe code.
        std::mem::take(self).into_bytes().zeroize();
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Zeroizing<T: Zeroize>(T);
impl<T: Zeroize + Default> Default for Zeroizing<T> {
    fn default() -> Self {
        Self(T::default())
    }
}
impl<T: Zeroize> Zeroizing<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
}
impl<T: Zeroize> Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T: Zeroize> DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
impl<T: Zeroize + AsRef<U>, U: ?Sized> AsRef<U> for Zeroizing<T> {
    fn as_ref(&self) -> &U {
        self.0.as_ref()
    }
}
impl<T: Zeroize + AsMut<U>, U: ?Sized> AsMut<U> for Zeroizing<T> {
    fn as_mut(&mut self) -> &mut U {
        self.0.as_mut()
    }
}
impl<T: Zeroize> std::fmt::Debug for Zeroizing<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Zeroizing([REDACTED])")
    }
}
impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_debug_is_redacted_and_owned_buffers_are_cleared() {
        let value = Zeroizing::new("do not disclose".to_string());
        assert_eq!(format!("{value:?}"), "Zeroizing([REDACTED])");
        let mut bytes = vec![42u8; 64];
        bytes.truncate(4);
        let capacity = bytes.capacity();
        bytes.zeroize();
        assert!(bytes.is_empty());
        assert_eq!(bytes.capacity(), capacity);
        let mut text = "secret".to_string();
        text.zeroize();
        assert!(text.is_empty());
        let mut words = [u32::MAX; 5];
        words.zeroize();
        assert_eq!(words, [0; 5]);
    }
    #[test]
    fn drop_calls_the_erasure_contract() {
        struct Probe(std::rc::Rc<std::cell::Cell<bool>>);
        impl Zeroize for Probe {
            fn zeroize(&mut self) {
                self.0.set(true);
            }
        }
        let erased = std::rc::Rc::new(std::cell::Cell::new(false));
        drop(Zeroizing::new(Probe(erased.clone())));
        assert!(erased.get());
    }
}
