//! A key -> value map meant to be used with patch handles.
//! - Uses Arc to keep track when all keys are dropped.
//! - Doesn't allow/require specifying keys on insert, just gives you one.
//! - Currently doesn't really free memory, just reuses it.

use std::sync::Arc;

#[derive(Clone)]
pub struct Key(Arc<u32>);

enum Entry<Value> {
    Empty,
    Occupied(Value),
}

pub struct PatchMap<Value> {
    active_entries: Vec<Entry<Value>>,
    // Deleted entries which still have valid keys active.
    deleted_entries: Vec<Arc<u32>>,
}

impl<Value> PatchMap<Value> {
    pub const fn new() -> PatchMap<Value> {
        PatchMap {
            active_entries: Vec::new(),
            deleted_entries: Vec::new(),
        }
    }

    pub fn insert(&mut self, val: Value) -> Key {
        let key = self.new_key();
        self.active_entries[*key.0 as usize] = Entry::Occupied(val);
        key
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

    pub fn get(&self, key: &Key) -> Option<&Value> {
        match self.active_entries[*key.0 as usize] {
            Entry::Empty => None,
            Entry::Occupied(ref val) => Some(val),
        }
    }

    pub fn get_mut(&mut self, key: &Key) -> Option<&mut Value> {
        match self.active_entries[*key.0 as usize] {
            Entry::Empty => None,
            Entry::Occupied(ref mut val) => Some(val),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn search() {
        let mut map = PatchMap::<i32>::new();
        map.insert(6);
        let key = map.insert(52);
        let key2 = map.insert(1);
        map.insert(96);
        assert_eq!(map.get(&key).cloned(), Some(52));
        *map.get_mut(&key2).unwrap() += 2;
        assert_eq!(map.get(&key2).cloned(), Some(3));
    }
}
