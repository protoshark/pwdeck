use std::ops::Deref;
use std::{fmt, ptr};

use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};

/// SecVec automatically overwrites its data from memory when dropped
pub struct SecVec<T> {
    data: Vec<T>,
}

impl<T> SecVec<T> {
    pub fn new(vec: Vec<T>) -> Self {
        Self { data: vec }
    }
}

impl<T> Deref for SecVec<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> From<Vec<T>> for SecVec<T> {
    fn from(vec: Vec<T>) -> Self {
        Self::new(vec)
    }
}

impl<T> Drop for SecVec<T> {
    fn drop(&mut self) {
        unsafe {
            ptr::write_volatile(self.data.as_mut_ptr() as *mut u8, 0);
        }
        self.data.clear();
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// SecString automatically overwrites its data from memory when dropped
pub struct SecString {
    data: String,
}

impl SecString {
    pub fn new(data: String) -> Self {
        Self { data }
    }
}

impl Deref for SecString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl From<String> for SecString {
    fn from(data: String) -> Self {
        Self::new(data)
    }
}

impl<'a> From<&'a str> for SecString {
    fn from(data: &'a str) -> Self {
        Self::new(String::from(data))
    }
}

impl Drop for SecString {
    fn drop(&mut self) {
        unsafe {
            ptr::write_volatile(self.data.as_mut_ptr(), 0);
        }
        self.data.clear();
    }
}

impl Serialize for SecString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.deref())
    }
}

impl<'de> Deserialize<'de> for SecString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SecVisitor;

        impl<'de> Visitor<'de> for SecVisitor {
            type Value = SecString;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("String")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Ok(SecString::from(s))
            }
        }

        deserializer
            .deserialize_str(SecVisitor)
            .map(|v| SecString::from(v))
    }
}
