//! A key -> value map meant to be used with patch handles.
//! - Uses Arc to keep track when all keys are dropped.
//! - Doesn't allow/require specifying keys on insert, just gives you one.
//! - Currently doesn't really free memory, just reuses it.

use std::slice;
use std::sync::Arc;

#[derive(Clone)]
pub struct Key(Arc<u32>);

enum Entry<Value> {
    Empty,
    Occupied(Key, Value),
}

pub struct PatchMap<Value> {
    active_entries: Vec<Entry<Value>>,
    // Deleted entries which still have valid keys active.
    deleted_entries: Vec<Arc<u32>>,
}

pub struct Iter<'a, T: 'a>(slice::Iter<'a, Entry<T>>);
pub struct IterMut<'a, T: 'a>(slice::IterMut<'a, Entry<T>>);

impl<Value> PatchMap<Value> {
    pub fn new() -> PatchMap<Value> {
        PatchMap {
            active_entries: Vec::new(),
            deleted_entries: Vec::new(),
        }
    }

    // Allowing some dead code for now as the api would be odd otherwise.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn insert(&mut self, val: Value) -> Key {
        let key = self.new_key();
        self.active_entries[*key.0 as usize] = Entry::Occupied(key.clone(), val);
        key
    }

    /// Allocates a empty slot which must be reassigned with `assign` or deleted or else the
    /// slot will be leaked.
    pub fn alloc_slot(&mut self) -> Key {
        self.new_key()
    }

    fn new_key(&mut self) -> Key {
        for i in (0..self.deleted_entries.len()).rev() {
            let deleted = self.deleted_entries.swap_remove(i);
            match Arc::try_unwrap(deleted) {
                Ok(key) => return Key(Arc::new(key)),
                Err(arc) => self.deleted_entries.push(arc),
            }
        }
        self.active_entries.push(Entry::Empty);
        Key(Arc::new(self.active_entries.len() as u32 - 1))
    }

    /// Assigns a value to key which can have been allocated with `alloc_slot`.
    /// Panics if there is no such slot in the map (which should only happen if
    /// the key belongs to a separate map).
    pub fn assign(&mut self, key: Key, val: Value) {
        let index = *key.0 as usize;
        self.active_entries[index] = Entry::Occupied(key, val);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn iter(&self) -> Iter<Value> {
        Iter(self.active_entries.iter())
    }

    pub fn iter_mut(&mut self) -> IterMut<Value> {
        IterMut(self.active_entries.iter_mut())
    }
}

impl<'a, T: 'a> Iterator for Iter<'a, T> {
    type Item = &'a T;
    fn next(&mut self) -> Option<&'a T> {
        loop {
            match self.0.next() {
                Some(&Entry::Occupied(_, ref val)) => return Some(val),
                Some(&Entry::Empty) => (),
                None => return None,
            }
        }
    }
}

impl<'a, T: 'a> Iterator for IterMut<'a, T> {
    type Item = &'a mut T;
    fn next(&mut self) -> Option<&'a mut T> {
        loop {
            match self.0.next() {
                Some(&mut Entry::Occupied(_, ref mut val)) => return Some(val),
                Some(&mut Entry::Empty) => (),
                None => return None,
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn iterate() {
        let mut map = PatchMap::<i32>::new();
        map.insert(6);
        map.insert(52);
        map.insert(1);
        map.insert(96);
        let mut items = map.iter().cloned().collect::<Vec<_>>();
        items.sort();
        assert_eq!(items, vec![1, 6, 52, 96]);

        for item in map.iter_mut() {
            *item += 1;
        }
        let mut items = map.iter().cloned().collect::<Vec<_>>();
        items.sort();
        assert_eq!(items, vec![2, 7, 53, 97]);
    }
}
