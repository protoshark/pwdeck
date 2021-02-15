use std::ops::Deref;
use std::{fmt, ptr};

use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};

/// SecString automatically overwrites its data from memory when dropped
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SecString(String);

impl Deref for SecString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for SecString {
    fn from(data: String) -> Self {
        Self(data)
    }
}

impl<'a> From<&'a str> for SecString {
    fn from(data: &'a str) -> Self {
        Self(String::from(data))
    }
}

impl Drop for SecString {
    fn drop(&mut self) {
        if self.0.len() > 0 {
            unsafe {
                ptr::write_volatile(self.0.as_mut_ptr(), 0);
            }
            self.0.clear();
        }
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
