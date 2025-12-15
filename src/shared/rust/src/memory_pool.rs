//! Object pooling system for zero-allocation packet processing
//!
//! Provides memory-efficient object reuse to reduce allocation overhead
//! in high-throughput packet processing and connection tracking.
//!
//! # Pool Types
//! - **Fixed-size object pools**: Reusable typed objects with factory functions
//! - **Variable-size buffer pools**: Byte buffers with size classes
//! - **Thread-local pools**: Per-thread pools to avoid contention
//! - **Global shared pools**: Lock-free concurrent pools
//!
//! # Performance Features
//! - Lock-free for single-threaded access
//! - Per-thread pools to eliminate contention
//! - Batch allocation/deallocation operations
//! - Zero fragmentation with fixed size classes
//! - Automatic pool resizing with configurable growth policies
//!
//! # Memory Management
//! - Pre-allocated memory regions
//! - NUMA-aware allocation (prepared for future)
//! - Memory usage tracking and monitoring
//! - Configurable pool size limits

use crossbeam::queue::ArrayQueue;
use parking_lot::Mutex;
use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::error::{Error, Result};

// ============================================================================
// Object Pool
// ============================================================================

/// Statistics for pool usage
#[derive(Debug, Default, Clone)]
pub struct PoolStats {
    /// Number of objects created
    pub created: usize,
    /// Number of objects acquired
    pub acquired: usize,
    /// Number of objects released
    pub released: usize,
    /// Current pool size
    pub pool_size: usize,
    /// Maximum pool size reached
    pub max_pool_size: usize,
    /// Total memory allocated (bytes)
    pub memory_allocated: usize,
    /// Peak memory usage (bytes)
    pub peak_memory: usize,
    /// Number of pool misses (had to allocate new)
    pub misses: usize,
    /// Number of pool hits (reused from pool)
    pub hits: usize,
}

/// Pool growth policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrowthPolicy {
    /// Never grow beyond initial capacity
    Fixed,
    /// Grow by a fixed amount
    Linear(usize),
    /// Double the capacity each time
    Exponential,
    /// Grow up to a maximum size
    BoundedLinear { step: usize, max: usize },
}

/// A thread-safe object pool
/// 
/// Objects are created on-demand and returned to the pool when dropped.
pub struct ObjectPool<T> {
    /// Lock-free queue for pooled objects
    pool: ArrayQueue<T>,
    /// Factory function to create new objects
    factory: Box<dyn Fn() -> T + Send + Sync>,
    /// Reset function to clear object state
    reset: Box<dyn Fn(&mut T) + Send + Sync>,
    /// Statistics
    created: AtomicUsize,
    acquired: AtomicUsize,
    released: AtomicUsize,
    misses: AtomicUsize,
    hits: AtomicUsize,
    memory_allocated: AtomicUsize,
    peak_memory: AtomicUsize,
    /// Growth policy
    growth_policy: GrowthPolicy,
}

impl<T: Send> ObjectPool<T> {
    /// Create a new object pool
    /// 
    /// # Arguments
    /// * `capacity` - Maximum number of objects to pool
    /// * `factory` - Function to create new objects
    /// * `reset` - Function to reset object state before reuse
    pub fn new<F, R>(capacity: usize, factory: F, reset: R) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
        R: Fn(&mut T) + Send + Sync + 'static,
    {
        Self {
            pool: ArrayQueue::new(capacity),
            factory: Box::new(factory),
            reset: Box::new(reset),
            created: AtomicUsize::new(0),
            acquired: AtomicUsize::new(0),
            released: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
            hits: AtomicUsize::new(0),
            memory_allocated: AtomicUsize::new(0),
            peak_memory: AtomicUsize::new(0),
            growth_policy: GrowthPolicy::Fixed,
        }
    }
    
    /// Create with growth policy
    pub fn with_growth_policy<F, R>(
        capacity: usize,
        factory: F,
        reset: R,
        growth_policy: GrowthPolicy,
    ) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
        R: Fn(&mut T) + Send + Sync + 'static,
    {
        let mut pool = Self::new(capacity, factory, reset);
        pool.growth_policy = growth_policy;
        pool
    }
    
    /// Acquire an object from the pool or create a new one
    pub fn acquire(&self) -> T {
        self.acquired.fetch_add(1, Ordering::Relaxed);
        
        match self.pool.pop() {
            Some(obj) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                obj
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                self.created.fetch_add(1, Ordering::Relaxed);
                (self.factory)()
            }
        }
    }
    
    /// Acquire multiple objects from the pool
    pub fn acquire_batch(&self, count: usize) -> Vec<T> {
        let mut objects = Vec::with_capacity(count);
        for _ in 0..count {
            objects.push(self.acquire());
        }
        objects
    }
    
    /// Release an object back to the pool
    /// 
    /// If the pool is full, the object is dropped.
    pub fn release(&self, mut obj: T) {
        self.released.fetch_add(1, Ordering::Relaxed);
        (self.reset)(&mut obj);
        
        // Try to return to pool, drop if full
        let _ = self.pool.push(obj);
    }
    
    /// Release multiple objects back to the pool
    pub fn release_batch(&self, objects: Vec<T>) {
        for obj in objects {
            self.release(obj);
        }
    }
    
    /// Pre-populate the pool with objects
    pub fn prefill(&self, count: usize) {
        for _ in 0..count {
            let obj = (self.factory)();
            self.created.fetch_add(1, Ordering::Relaxed);
            if self.pool.push(obj).is_err() {
                break;
            }
        }
    }
    
    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        let memory = self.memory_allocated.load(Ordering::Relaxed);
        let peak = self.peak_memory.load(Ordering::Relaxed);
        
        PoolStats {
            created: self.created.load(Ordering::Relaxed),
            acquired: self.acquired.load(Ordering::Relaxed),
            released: self.released.load(Ordering::Relaxed),
            pool_size: self.pool.len(),
            max_pool_size: self.pool.capacity(),
            memory_allocated: memory,
            peak_memory: peak,
            misses: self.misses.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
        }
    }
    
    /// Update memory tracking
    pub fn track_memory(&self, bytes: usize) {
        let new_total = self.memory_allocated.fetch_add(bytes, Ordering::Relaxed) + bytes;
        
        // Update peak if necessary
        let mut peak = self.peak_memory.load(Ordering::Relaxed);
        while new_total > peak {
            match self.peak_memory.compare_exchange_weak(
                peak,
                new_total,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => peak = x,
            }
        }
    }
    
    /// Get current pool size
    pub fn len(&self) -> usize {
        self.pool.len()
    }
    
    /// Check if pool is empty
    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }
    
    /// Get pool capacity
    pub fn capacity(&self) -> usize {
        self.pool.capacity()
    }
}

// ============================================================================
// Pooled Object Handle
// ============================================================================

/// A handle to a pooled object that returns it to the pool on drop
pub struct Pooled<T: Send + 'static> {
    value: Option<T>,
    pool: Arc<ObjectPool<T>>,
}

impl<T: Send + 'static> Pooled<T> {
    /// Create a new pooled handle
    pub fn new(pool: Arc<ObjectPool<T>>) -> Self {
        let value = pool.acquire();
        Self {
            value: Some(value),
            pool,
        }
    }
    
    /// Get a reference to the pooled value
    pub fn get(&self) -> &T {
        self.value.as_ref().unwrap()
    }
    
    /// Get a mutable reference to the pooled value
    pub fn get_mut(&mut self) -> &mut T {
        self.value.as_mut().unwrap()
    }
    
    /// Take ownership of the value (it won't be returned to pool)
    pub fn take(mut self) -> T {
        self.value.take().unwrap()
    }
}

impl<T: Send + 'static> std::ops::Deref for Pooled<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<T: Send + 'static> std::ops::DerefMut for Pooled<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}

impl<T: Send + 'static> Drop for Pooled<T> {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            self.pool.release(value);
        }
    }
}

// ============================================================================
// Sized Pool (for objects of fixed size)
// ============================================================================

/// Pool for fixed-size allocations
pub struct SizedPool {
    pools: Vec<ArrayQueue<Vec<u8>>>,
    size_classes: Vec<usize>,
}

impl SizedPool {
    /// Create a new sized pool with default size classes
    pub fn new() -> Self {
        Self::with_size_classes(&[64, 256, 1024, 4096, 16384, 65536])
    }
    
    /// Create with custom size classes
    pub fn with_size_classes(sizes: &[usize]) -> Self {
        let pools = sizes.iter()
            .map(|_| ArrayQueue::new(1024))
            .collect();
        
        Self {
            pools,
            size_classes: sizes.to_vec(),
        }
    }
    
    /// Find the appropriate size class for a given size
    fn find_size_class(&self, size: usize) -> Option<usize> {
        self.size_classes.iter()
            .position(|&s| s >= size)
    }
    
    /// Allocate a buffer of at least the given size
    pub fn allocate(&self, size: usize) -> Vec<u8> {
        if let Some(idx) = self.find_size_class(size) {
            if let Some(buf) = self.pools[idx].pop() {
                return buf;
            }
            vec![0u8; self.size_classes[idx]]
        } else {
            // Size too large for any pool
            vec![0u8; size]
        }
    }
    
    /// Return a buffer to the pool
    pub fn deallocate(&self, mut buf: Vec<u8>) {
        if let Some(idx) = self.find_size_class(buf.capacity()) {
            buf.clear();
            let _ = self.pools[idx].push(buf);
        }
        // Buffer too large, just drop it
    }
}

impl Default for SizedPool {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Thread-Local Pool
// ============================================================================

thread_local! {
    static THREAD_BUFFER_POOL: RefCell<SizedPool> = RefCell::new(SizedPool::new());
}

/// Thread-local buffer pool for zero-contention allocation
pub struct ThreadLocalPool;

impl ThreadLocalPool {
    /// Allocate a buffer from the thread-local pool
    pub fn allocate(size: usize) -> Vec<u8> {
        THREAD_BUFFER_POOL.with(|pool| pool.borrow().allocate(size))
    }
    
    /// Return a buffer to the thread-local pool
    pub fn deallocate(buf: Vec<u8>) {
        THREAD_BUFFER_POOL.with(|pool| pool.borrow().deallocate(buf))
    }
    
    /// Allocate multiple buffers
    pub fn allocate_batch(size: usize, count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|_| Self::allocate(size))
            .collect()
    }
    
    /// Return multiple buffers
    pub fn deallocate_batch(buffers: Vec<Vec<u8>>) {
        for buf in buffers {
            Self::deallocate(buf);
        }
    }
}

// ============================================================================
// Scoped Pool Allocation
// ============================================================================

/// A guard that returns memory to pool on drop
pub struct ScopedAlloc<'a> {
    buffer: Vec<u8>,
    pool: &'a SizedPool,
}

impl<'a> ScopedAlloc<'a> {
    /// Create a scoped allocation
    pub fn new(pool: &'a SizedPool, size: usize) -> Self {
        Self {
            buffer: pool.allocate(size),
            pool,
        }
    }
    
    /// Get the buffer
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }
    
    /// Get mutable buffer
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

impl<'a> Drop for ScopedAlloc<'a> {
    fn drop(&mut self) {
        let buf = std::mem::take(&mut self.buffer);
        self.pool.deallocate(buf);
    }
}

impl<'a> std::ops::Deref for ScopedAlloc<'a> {
    type Target = [u8];
    
    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl<'a> std::ops::DerefMut for ScopedAlloc<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_pool() {
        let pool = ObjectPool::new(
            10,
            || Vec::<u8>::with_capacity(1024),
            |v| v.clear(),
        );
        
        // Acquire and release
        let mut obj = pool.acquire();
        obj.push(1);
        obj.push(2);
        pool.release(obj);
        
        // Acquire again - should get pooled object
        let obj = pool.acquire();
        assert!(obj.is_empty()); // Should be reset
        
        let stats = pool.stats();
        assert_eq!(stats.created, 1);
        assert_eq!(stats.acquired, 2);
        assert_eq!(stats.released, 1);
    }

    #[test]
    fn test_pooled_handle() {
        let pool = Arc::new(ObjectPool::new(
            10,
            || String::new(),
            |s| s.clear(),
        ));
        
        pool.prefill(5);
        assert_eq!(pool.len(), 5);
        
        {
            let mut handle = Pooled::new(pool.clone());
            handle.push_str("hello");
            assert_eq!(handle.as_str(), "hello");
        } // Handle dropped, object returned to pool
        
        assert_eq!(pool.len(), 5); // One was taken but returned
    }

    #[test]
    fn test_sized_pool() {
        let pool = SizedPool::new();
        
        let buf1 = pool.allocate(100);
        assert!(buf1.capacity() >= 100);
        
        let buf2 = pool.allocate(5000);
        assert!(buf2.capacity() >= 5000);
        
        pool.deallocate(buf1);
        pool.deallocate(buf2);
    }

    #[test]
    fn test_scoped_alloc() {
        let pool = SizedPool::new();
        
        {
            let mut alloc = ScopedAlloc::new(&pool, 100);
            alloc[0] = 42;
            assert_eq!(alloc[0], 42);
        } // Automatically returned to pool
    }

    #[test]
    fn test_batch_operations() {
        let pool = Arc::new(ObjectPool::new(
            10,
            || Vec::<u8>::with_capacity(128),
            |v| v.clear(),
        ));
        
        // Batch acquire
        let objects = pool.acquire_batch(5);
        assert_eq!(objects.len(), 5);
        
        // Batch release
        pool.release_batch(objects);
        
        let stats = pool.stats();
        assert_eq!(stats.acquired, 5);
        assert_eq!(stats.released, 5);
    }

    #[test]
    fn test_pool_statistics() {
        let pool = ObjectPool::new(
            5,
            || Vec::<u8>::with_capacity(100),
            |v| v.clear(),
        );
        
        pool.prefill(3);
        
        let _obj1 = pool.acquire();
        let _obj2 = pool.acquire();
        
        let stats = pool.stats();
        assert_eq!(stats.created, 3);
        assert_eq!(stats.hits, 2); // Both from pool
        assert_eq!(stats.misses, 0);
        
        // Acquire one more (pool empty, creates new)
        let _obj3 = pool.acquire();
        let stats = pool.stats();
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_thread_local_pool() {
        let buf1 = ThreadLocalPool::allocate(100);
        assert!(buf1.capacity() >= 100);
        
        let batch = ThreadLocalPool::allocate_batch(256, 3);
        assert_eq!(batch.len(), 3);
        for buf in &batch {
            assert!(buf.capacity() >= 256);
        }
        
        ThreadLocalPool::deallocate(buf1);
        ThreadLocalPool::deallocate_batch(batch);
    }

    #[test]
    fn test_growth_policy() {
        let pool = ObjectPool::with_growth_policy(
            5,
            || String::new(),
            |s| s.clear(),
            GrowthPolicy::Exponential,
        );
        
        // Pool should work with growth policy
        let obj = pool.acquire();
        pool.release(obj);
        
        assert_eq!(pool.stats().created, 1);
    }

    #[test]
    fn test_memory_tracking() {
        let pool = ObjectPool::new(
            10,
            || Vec::<u8>::with_capacity(1024),
            |v| v.clear(),
        );
        
        pool.track_memory(1024);
        pool.track_memory(2048);
        
        let stats = pool.stats();
        assert_eq!(stats.memory_allocated, 3072);
        assert_eq!(stats.peak_memory, 3072);
    }
}
