use std::ops::{Deref, DerefMut};

/// Structure used to reassemble data arriving in fragments.
/// Supposed to handle out of order arrival, but does not at the moment.
pub struct Buffer {
    data: Vec<u8>,
    lowest_missing: usize,
}

impl Buffer {
    pub fn new(capacity: usize) -> Buffer {
        Buffer {
            data: vec![0; capacity],
            lowest_missing: 0,
        }
    }

    /// Push new data to this `Buffer`. Returns the lowest index of missing
    /// data on success.
    /// This is equivalent to the length of the valid data at the start of the
    /// buffer. Will fail if the given data offset is not valid.
    // TODO: Support out of order data
    pub fn push(&mut self, offset: usize, data: &[u8]) -> Result<usize, ()> {
        if offset == self.lowest_missing {
            self.lowest_missing += data.len();
        } else {
            return Err(());
        }
        self.data[offset..offset + data.len()].copy_from_slice(data);
        Ok(self.lowest_missing)
    }

    /// Consumes the `Buffer` and returns the data in an owned slice
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

impl Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data[..self.lowest_missing]
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.lowest_missing]
    }
}


#[cfg(test)]
mod tests {
    // TODO: Write unit tests
}
