use std::ops::Deref;
use std::ptr;

/// SecVec automatically overwrites its data from memory when dropped
pub struct SecVec<T>(Vec<T>);

impl<T> Deref for SecVec<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<Vec<T>> for SecVec<T> {
    fn from(vec: Vec<T>) -> Self {
        Self(vec)
    }
}

impl<T> Drop for SecVec<T> {
    fn drop(&mut self) {
        unsafe {
            ptr::write_volatile(self.0.as_mut_ptr() as *mut u8, 0);
        }
        self.0.clear();
    }
}
