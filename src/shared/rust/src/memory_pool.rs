//! Object pooling for high-frequency allocations in packet processing
//!
//! Provides pre-allocated, reusable objects that are reset and returned to pool
//! after use, enabling zero-allocation packet handling. Implements generic pool
//! that works with any type, uses Drop trait for automatic return to pool.

use crate::error::{Result, SafeOpsError};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// Trait for types that can be reset to initial state before reuse
pub trait Resettable {
    /// Resets the object to its initial state
    fn reset(&mut self);
}

// Implement Resettable for common types
impl<T> Resettable for Vec<T> {
    fn reset(&mut self) {
        self.clear();
    }
}

impl Resettable for String {
    fn reset(&mut self) {
        self.clear();
    }
}

/// Pool statistics for monitoring
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Number of objects currently available in pool
    pub available: usize,
    /// Number of objects currently checked out
    pub in_use: usize,
    /// Total number of acquire calls over pool lifetime
    pub total_allocations: u64,
    /// Number of times pool was exhausted and had to allocate
    pub pool_exhaustions: u64,
    /// Maximum pool capacity
    pub capacity: usize,
}

/// Generic object pool for high-frequency allocations
///
/// Preallocates objects and reuses them to eliminate allocation overhead
/// in hot paths. Thread-safe and supports any type T.
pub struct MemoryPool<T> {
    /// Maximum pool size
    capacity: usize,
    /// Free objects available for use
    available: Arc<Mutex<Vec<T>>>,
    /// Total number of objects allocated over pool lifetime
    total_allocated: AtomicUsize,
    /// Number of objects currently in use
    current_in_use: AtomicUsize,
    /// Total number of acquire calls
    allocation_count: AtomicU64,
    /// Number of times pool was exhausted
    exhaustion_count: AtomicU64,
}

impl<T> MemoryPool<T>
where
    T: Default,
{
    /// Creates a new memory pool with specified capacity
    ///
    /// Preallocates `capacity` objects using T::default()
    pub fn new(capacity: usize) -> Self {
        Self::with_initializer(capacity, T::default)
    }
}

impl<T> MemoryPool<T> {
    /// Creates a new memory pool with custom object initializer
    ///
    /// Calls `init` function for each object during preallocation
    pub fn with_initializer<F>(capacity: usize, init: F) -> Self
    where
        F: Fn() -> T,
    {
        let mut objects = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            objects.push(init());
        }

        MemoryPool {
            capacity,
            available: Arc::new(Mutex::new(objects)),
            total_allocated: AtomicUsize::new(capacity),
            current_in_use: AtomicUsize::new(0),
            allocation_count: AtomicU64::new(0),
            exhaustion_count: AtomicU64::new(0),
        }
    }

    /// Acquires an object from the pool
    ///
    /// Returns a PooledObject smart pointer that automatically returns
    /// the object to the pool when dropped. If pool is empty, allocates
    /// a new object (with warning).
    pub fn acquire(&self) -> Result<PooledObject<T>>
    where
        T: Default,
    {
        self.allocation_count.fetch_add(1, Ordering::Relaxed);

        // Try to get object from pool
        let obj = {
            let mut available = self.available.lock().unwrap();
            available.pop()
        };

        let obj = match obj {
            Some(obj) => obj,
            None => {
                // Pool exhausted - allocate new object
                self.exhaustion_count.fetch_add(1, Ordering::Relaxed);
                
                #[cfg(feature = "warn_pool_exhaustion")]
                eprintln!("Warning: Memory pool exhausted, allocating new object");
                
                self.total_allocated.fetch_add(1, Ordering::Relaxed);
                T::default()
            }
        };

        self.current_in_use.fetch_add(1, Ordering::Relaxed);

        Ok(PooledObject {
            obj: Some(obj),
            pool: Arc::downgrade(&self.available),
        })
    }

    /// Tries to acquire object from pool without allocating
    ///
    /// Returns None if pool is empty (doesn't allocate new objects)
    pub fn try_acquire(&self) -> Option<PooledObject<T>> {
        self.allocation_count.fetch_add(1, Ordering::Relaxed);

        let obj = {
            let mut available = self.available.lock().unwrap();
            available.pop()
        }?;

        self.current_in_use.fetch_add(1, Ordering::Relaxed);

        Some(PooledObject {
            obj: Some(obj),
            pool: Arc::downgrade(&self.available),
        })
    }

    /// Preallocates additional objects and adds them to pool
    pub fn preallocate(&self, count: usize)
    where
        T: Default,
    {
        let mut available = self.available.lock().unwrap();
        for _ in 0..count {
            available.push(T::default());
        }
        self.total_allocated.fetch_add(count, Ordering::Relaxed);
    }

    /// Removes excess objects from pool to reduce memory footprint
    pub fn shrink(&self, target_size: usize) {
        let mut available = self.available.lock().unwrap();
        if available.len() > target_size {
            let removed = available.len() - target_size;
            available.truncate(target_size);
            // Also update total_allocated since we removed objects
            self.total_allocated.fetch_sub(removed, Ordering::Relaxed);
        }
    }

    /// Clears all objects from pool and resets counters
    pub fn clear(&self) {
        let mut available = self.available.lock().unwrap();
        available.clear();
        self.current_in_use.store(0, Ordering::Relaxed);
    }

    /// Drains and returns all objects from pool
    pub fn drain(&self) -> Vec<T> {
        let mut available = self.available.lock().unwrap();
        available.drain(..).collect()
    }

    /// Returns pool statistics
    pub fn stats(&self) -> PoolStats {
        let available = self.available.lock().unwrap().len();
        let total_allocated = self.total_allocated.load(Ordering::Relaxed);
        PoolStats {
            available,
            // Compute in_use from total allocated minus available
            in_use: total_allocated.saturating_sub(available),
            total_allocations: self.allocation_count.load(Ordering::Relaxed),
            pool_exhaustions: self.exhaustion_count.load(Ordering::Relaxed),
            capacity: self.capacity,
        }
    }

    /// Returns pool utilization as percentage (0.0 to 1.0)
    pub fn utilization(&self) -> f32 {
        let in_use = self.current_in_use.load(Ordering::Relaxed);
        let total = self.total_allocated.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            in_use as f32 / total as f32
        }
    }

    /// Returns true if pool has no available objects
    pub fn is_exhausted(&self) -> bool {
        self.available.lock().unwrap().is_empty()
    }
}

/// Smart pointer wrapper for pooled objects
///
/// Automatically returns object to pool when dropped
pub struct PooledObject<T> {
    obj: Option<T>,
    pool: Weak<Mutex<Vec<T>>>,
}

impl<T> PooledObject<T> {
    /// Returns immutable reference to inner object
    pub fn as_ref(&self) -> &T {
        self.obj.as_ref().unwrap()
    }

    /// Returns mutable reference to inner object
    pub fn as_mut(&mut self) -> &mut T {
        self.obj.as_mut().unwrap()
    }

    /// Resets object state if it implements Resettable
    pub fn reset(&mut self)
    where
        T: Resettable,
    {
        if let Some(obj) = &mut self.obj {
            obj.reset();
        }
    }

    /// Detaches object from pool (won't be returned on drop)
    pub fn detach(mut self) -> T {
        self.pool = Weak::new();
        self.obj.take().unwrap()
    }
}

impl<T> Deref for PooledObject<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.obj.as_ref().unwrap()
    }
}

impl<T> DerefMut for PooledObject<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.obj.as_mut().unwrap()
    }
}

impl<T> Drop for PooledObject<T> {
    fn drop(&mut self) {
        if let Some(obj) = self.obj.take() {
            // Return to pool if pool still exists
            if let Some(pool) = self.pool.upgrade() {
                if let Ok(mut available) = pool.lock() {
                    available.push(obj);
                }
            }
        }
    }
}

unsafe impl<T: Send> Send for MemoryPool<T> {}
unsafe impl<T: Send> Sync for MemoryPool<T> {}
unsafe impl<T: Send> Send for PooledObject<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, Debug)]
    struct TestObject {
        value: usize,
    }

    impl Resettable for TestObject {
        fn reset(&mut self) {
            self.value = 0;
        }
    }

    #[test]
    fn test_pool_creation() {
        let pool: MemoryPool<TestObject> = MemoryPool::new(10);
        let stats = pool.stats();
        assert_eq!(stats.available, 10);
        assert_eq!(stats.in_use, 0);
    }

    #[test]
    fn test_acquire_and_return() {
        let pool: MemoryPool<TestObject> = MemoryPool::new(5);
        
        {
            let obj = pool.acquire().unwrap();
            assert_eq!(pool.stats().in_use, 1);
            assert_eq!(pool.stats().available, 4);
        }
        
        // Object should be returned after drop
        assert_eq!(pool.stats().in_use, 0);
        assert_eq!(pool.stats().available, 5);
    }

    #[test]
    fn test_pool_exhaustion() {
        let pool: MemoryPool<TestObject> = MemoryPool::new(2);
        
        let _obj1 = pool.acquire().unwrap();
        let _obj2 = pool.acquire().unwrap();
        
        assert!(pool.is_exhausted());
        
        // Should still work, allocating new object
        let _obj3 = pool.acquire().unwrap();
        assert_eq!(pool.stats().pool_exhaustions, 1);
    }

    #[test]
    fn test_try_acquire() {
        let pool: MemoryPool<TestObject> = MemoryPool::new(1);
        
        let _obj1 = pool.try_acquire().unwrap();
        let obj2 = pool.try_acquire();
        
        assert!(obj2.is_none()); // Pool empty, doesn't allocate
    }

    #[test]
    fn test_utilization() {
        let pool: MemoryPool<TestObject> = MemoryPool::new(10);
        
        let _obj1 = pool.acquire().unwrap();
        let _obj2 = pool.acquire().unwrap();
        
        let util = pool.utilization();
        assert!(util > 0.0 && util <= 1.0);
    }

    #[test]
    fn test_preallocate() {
        let pool: MemoryPool<TestObject> = MemoryPool::new(5);
        pool.preallocate(5);
        
        assert_eq!(pool.stats().available, 10);
    }

    #[test]
    fn test_shrink() {
        let pool: MemoryPool<TestObject> = MemoryPool::new(10);
        pool.shrink(5);
        
        assert_eq!(pool.stats().available, 5);
    }

    #[test]
    fn test_vec_resettable() {
        let pool: MemoryPool<Vec<u8>> = MemoryPool::new(2);
        
        {
            let mut obj = pool.acquire().unwrap();
            obj.push(1);
            obj.push(2);
            obj.push(3);
        }
        
        // Object should be cleared when returned
        let obj = pool.acquire().unwrap();
        assert_eq!(obj.len(), 0);
    }
}
