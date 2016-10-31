use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

pub struct CacheMap<K, V> {
    map: HashMap<K, (Instant, V)>,
    timeout: Duration,
}

impl<K, V> CacheMap<K, V>
    where K: Hash + Eq
{
    pub fn new(timeout: Duration) -> CacheMap<K, V> {
        CacheMap {
            map: HashMap::new(),
            timeout: timeout,
        }
    }

    pub fn get<Q: ?Sized>(&mut self, k: &Q) -> Option<&V>
        where K: Borrow<Q>,
              Q: Hash + Eq
    {
        if let Some(&(ref i, ref v)) = self.map.get(k) {
            if i.elapsed() < self.timeout {
                Some(&v)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn get_mut<Q: ?Sized>(&mut self, k: &Q) -> Option<&mut V>
        where K: Borrow<Q>,
              Q: Hash + Eq
    {
        if let Some(&mut (ref i, ref mut v)) = self.map.get_mut(k) {
            if i.elapsed() < self.timeout {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn insert(&mut self, k: K, v: V) {
        self.map.insert(k, (Instant::now(), v));
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use std::time::Duration;

    use super::*;

    #[test]
    fn shortlived() {
        let mut testee = CacheMap::new(Duration::new(0, 0));
        testee.insert(0, 15);
        assert!(testee.get(&0).is_none());
        assert!(testee.get(&15).is_none());
    }

    #[test]
    fn normal() {
        let mut testee = CacheMap::new(Duration::new(0, 100_000_000));
        testee.insert(0, 15);
        assert_eq!(testee.get(&0), Some(&15));
        assert!(testee.get(&1).is_none());

        sleep(Duration::new(0, 50_000_000));
        assert_eq!(testee.get(&0), Some(&15));
        assert!(testee.get(&1).is_none());

        testee.insert(1, 99);
        assert_eq!(testee.get(&0), Some(&15));
        assert_eq!(testee.get(&1), Some(&99));

        sleep(Duration::new(0, 60_000_000));
        assert!(testee.get(&0).is_none());
        assert_eq!(testee.get(&1), Some(&99));

        sleep(Duration::new(0, 50_000_000));
        assert!(testee.get(&0).is_none());
        assert!(testee.get(&1).is_none());
    }
}
