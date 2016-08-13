use std::ops::{Deref, DerefMut};

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

    pub fn push(&mut self, offset: usize, data: &[u8]) -> Result<usize, ()> {
        if offset == self.lowest_missing {
            self.lowest_missing += data.len();
        } else {
            println!("{} != {}", offset, self.lowest_missing);
            return Err(())
        }
        self.data[offset..offset + data.len()].copy_from_slice(data);
        Ok(self.lowest_missing)
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
