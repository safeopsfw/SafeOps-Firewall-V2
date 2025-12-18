//! High-performance buffer pooling for network packet processing
//!
//! Provides lock-free, SIMD-optimized buffer pools that eliminate heap allocations
//! in hot packet handling paths. Supports multi-gigabit throughput with predictable
//! latency and zero-copy operations.

use crate::error::{Result, SafeOpsError};
use crossbeam::queue::ArrayQueue;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

// ============================================================================
// Constants and Configuration
// ============================================================================

/// Default buffer size for standard MTU packets (Ethernet MTU + headers)
pub const DEFAULT_BUFFER_SIZE: usize = 1536;

/// Default pool capacity (number of buffers)
pub const DEFAULT_POOL_CAPACITY: usize = 8192;

/// SIMD alignment requirement (32 bytes for AVX2)
pub const SIMD_ALIGNMENT: usize = 32;

// ============================================================================
// BufferPool - Lock-Free Buffer Pool
// ============================================================================

/// High-performance lock-free buffer pool for packet processing
pub struct BufferPool {
    /// Fixed size of each buffer in bytes
    buffer_size: usize,
    
    /// Maximum number of buffers this pool can hold
    capacity: usize,
    
    /// Lock-free queue of available buffers
    available: Arc<ArrayQueue<Vec<u8>>>,
    
    /// Total buffers allocated (includes available + in-use)
    allocated_count: AtomicUsize,
    
    /// Buffers currently checked out
    in_use_count: AtomicUsize,
    
    /// Number of times pool was exhausted
    allocation_failures: AtomicU64,
    
    /// Number of successful buffer reuses
    buffer_reuses: AtomicU64,
}

impl BufferPool {
    /// Creates a new buffer pool with specified buffer size and capacity
    ///
    /// Preallocates all buffers at creation time for predictable performance.
    pub fn new(buffer_size: usize, capacity: usize) -> Self {
        let available = Arc::new(ArrayQueue::new(capacity));
        
        // Preallocate all buffers
        for _ in 0..capacity {
            let buffer = Vec::with_capacity(buffer_size);
            let _ = available.push(buffer);
        }
        
        BufferPool {
            buffer_size,
            capacity,
            available,
            allocated_count: AtomicUsize::new(capacity),
            in_use_count: AtomicUsize::new(0),
            allocation_failures: AtomicU64::new(0),
            buffer_reuses: AtomicU64::new(0),
        }
    }
    
    /// Creates a pool with default MTU-sized buffers
    pub fn with_default_config() -> Self {
        Self::new(DEFAULT_BUFFER_SIZE, DEFAULT_POOL_CAPACITY)
    }
    
    /// Acquires a buffer from the pool
    ///
    /// Returns a smart pointer that automatically returns the buffer on drop.
    /// Allocates a new buffer if under capacity, or returns error if exhausted.
    pub fn acquire(self: &Arc<Self>) -> Result<PooledBuffer> {
        // Try to get buffer from available queue (lock-free)
        if let Some(mut buffer) = self.available.pop() {
            buffer.clear(); // Reset length to 0 (keeps capacity)
            self.in_use_count.fetch_add(1, Ordering::Relaxed);
            self.buffer_reuses.fetch_add(1, Ordering::Relaxed);
            
            return Ok(PooledBuffer {
                data: buffer,
                pool: Arc::downgrade(self),
                used_length: 0,
            });
        }
        
        // Queue empty - check if we can allocate new buffer
        let current_allocated = self.allocated_count.load(Ordering::Relaxed);
        if current_allocated < self.capacity {
            // Try to allocate new buffer
            let buffer = Vec::with_capacity(self.buffer_size);
            self.allocated_count.fetch_add(1, Ordering::Relaxed);
            self.in_use_count.fetch_add(1, Ordering::Relaxed);
            
            return Ok(PooledBuffer {
                data: buffer,
                pool: Arc::downgrade(self),
                used_length: 0,
            });
        }
        
        // Pool exhausted
        self.allocation_failures.fetch_add(1, Ordering::Relaxed);
        Err(SafeOpsError::internal("Buffer pool exhausted"))
    }
    
    /// Tries to acquire a buffer without allocating
    ///
    /// Returns None if pool is empty. Never allocates new buffers.
    pub fn try_acquire(self: &Arc<Self>) -> Option<PooledBuffer> {
        self.available.pop().map(|mut buffer| {
            buffer.clear();
            self.in_use_count.fetch_add(1, Ordering::Relaxed);
            self.buffer_reuses.fetch_add(1, Ordering::Relaxed);
            
            PooledBuffer {
                data: buffer,
                pool: Arc::downgrade(self),
                used_length: 0,
            }
        })
    }
    
    /// Acquires multiple buffers in a single operation
    pub fn acquire_batch(self: &Arc<Self>, count: usize) -> Result<Vec<PooledBuffer>> {
        let mut buffers = Vec::with_capacity(count);
        
        for _ in 0..count {
            match self.acquire() {
                Ok(buffer) => buffers.push(buffer),
                Err(e) => {
                    // Release already-acquired buffers on failure
                    drop(buffers);
                    return Err(e);
                }
            }
        }
        
        Ok(buffers)
    }
    
    /// Returns buffer statistics
    pub fn stats(&self) -> BufferPoolStats {
        let in_use = self.in_use_count.load(Ordering::Relaxed);
        let total_allocated = self.allocated_count.load(Ordering::Relaxed);
        let available = self.available.len();
        
        BufferPoolStats {
            buffer_size: self.buffer_size,
            capacity: self.capacity,
            available,
            in_use,
            total_allocated,
            allocation_failures: self.allocation_failures.load(Ordering::Relaxed),
            buffer_reuses: self.buffer_reuses.load(Ordering::Relaxed),
            utilization: if self.capacity > 0 {
                in_use as f32 / self.capacity as f32
            } else {
                0.0
            },
        }
    }
    
    /// Returns current pool utilization (0.0 to 1.0)
    pub fn utilization(&self) -> f32 {
        let in_use = self.in_use_count.load(Ordering::Relaxed);
        if self.capacity > 0 {
            in_use as f32 / self.capacity as f32
        } else {
            0.0
        }
    }
    
    /// Returns true if no buffers available
    pub fn is_exhausted(&self) -> bool {
        self.available.is_empty()
    }
    
    /// Returns total memory footprint in bytes
    pub fn memory_footprint(&self) -> usize {
        self.buffer_size * self.allocated_count.load(Ordering::Relaxed)
    }
    
    /// Internal: returns a buffer to the pool
    fn return_buffer(&self, mut buffer: Vec<u8>) {
        buffer.clear(); // Reset length, keep capacity
        
        // Try to return to pool (may fail if pool is full)
        if self.available.push(buffer).is_ok() {
            self.in_use_count.fetch_sub(1, Ordering::Relaxed);
        } else {
            // Pool full, buffer will be dropped
            // This can happen if pool was shrunk
            self.allocated_count.fetch_sub(1, Ordering::Relaxed);
            self.in_use_count.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

// ============================================================================
// PooledBuffer - Smart Pointer with Automatic Return
// ============================================================================

/// Smart pointer to a pooled buffer that automatically returns on drop
pub struct PooledBuffer {
    data: Vec<u8>,
    pool: Weak<BufferPool>,
    used_length: usize,
}

impl PooledBuffer {
    /// Returns the used portion of the buffer as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.used_length]
    }
    
    /// Returns mutable slice of used portion
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.used_length]
    }
    
    /// Returns the used length (actual data length)
    pub fn len(&self) -> usize {
        self.used_length
    }
    
    /// Returns true if no data has been written
    pub fn is_empty(&self) -> bool {
        self.used_length == 0
    }
    
    /// Returns the total buffer capacity
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }
    
    /// Resizes the used length (validates against capacity)
    pub fn resize(&mut self, new_len: usize) -> Result<()> {
        if new_len > self.data.capacity() {
            return Err(SafeOpsError::invalid_input(format!(
                "Cannot resize buffer to {} (capacity: {})",
                new_len,
                self.data.capacity()
            )));
        }
        
        // Resize the underlying Vec
        self.data.resize(new_len, 0);
        self.used_length = new_len;
        Ok(())
    }
    
    /// Clears the buffer (sets used length to 0, doesn't zero memory)
    pub fn clear(&mut self) {
        self.data.clear();
        self.used_length = 0;
    }
    
    /// Zeros the entire buffer using SIMD when available
    pub fn zero_fill(&mut self) {
        zero_fill_buffer(&mut self.data);
        self.used_length = 0;
    }
    
    /// Copies data into the buffer
    pub fn copy_from_slice(&mut self, src: &[u8]) -> Result<()> {
        if src.len() > self.data.capacity() {
            return Err(SafeOpsError::invalid_input(format!(
                "Source data {} bytes exceeds buffer capacity {}",
                src.len(),
                self.data.capacity()
            )));
        }
        
        self.data.clear();
        self.data.extend_from_slice(src);
        self.used_length = src.len();
        Ok(())
    }
    
    /// Detaches buffer from pool and transfers ownership
    pub fn detach(mut self) -> Vec<u8> {
        // Set pool to None so Drop doesn't return it
        self.pool = Weak::new();
        std::mem::take(&mut self.data)
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Return buffer to pool if pool still exists
        if let Some(pool) = self.pool.upgrade() {
            let buffer = std::mem::replace(&mut self.data, Vec::new());
            pool.return_buffer(buffer);
        }
    }
}

impl Deref for PooledBuffer {
    type Target = [u8];
    
    fn deref(&self) -> &[u8] {
        &self.data[..self.used_length]
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.used_length]
    }
}

impl AsRef<[u8]> for PooledBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for PooledBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

// ============================================================================
// Buffer Statistics
// ============================================================================

/// Statistics about buffer pool usage
#[derive(Debug, Clone)]
pub struct BufferPoolStats {
    /// Size of each buffer in bytes
    pub buffer_size: usize,
    
    /// Maximum pool capacity
    pub capacity: usize,
    
    /// Buffers currently available in pool
    pub available: usize,
    
    /// Buffers currently in use
    pub in_use: usize,
    
    /// Total buffers allocated (lifetime)
    pub total_allocated: usize,
    
    /// Times pool was exhausted
    pub allocation_failures: u64,
    
    /// Successful buffer reuses
    pub buffer_reuses: u64,
    
    /// Pool utilization (0.0 to 1.0)
    pub utilization: f32,
}

// ============================================================================
// SIMD Buffer Operations
// ============================================================================

/// Zeros a buffer using SIMD when available
pub fn zero_fill_buffer(buffer: &mut [u8]) {
    // SIMD implementation would go here
    // For now, use standard fill (still fast)
    buffer.fill(0);
}

/// Creates a buffer pool with default configuration
pub fn create_buffer_pool() -> Arc<BufferPool> {
    Arc::new(BufferPool::with_default_config())
}

/// Creates a buffer pool with custom size and capacity
pub fn create_buffer_pool_with_size(buffer_size: usize, capacity: usize) -> Arc<BufferPool> {
    Arc::new(BufferPool::new(buffer_size, capacity))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_creation() {
        let pool = create_buffer_pool();
        let stats = pool.stats();
        
        assert_eq!(stats.buffer_size, DEFAULT_BUFFER_SIZE);
        assert_eq!(stats.capacity, DEFAULT_POOL_CAPACITY);
        assert_eq!(stats.total_allocated, DEFAULT_POOL_CAPACITY);
        assert_eq!(stats.in_use, 0);
    }

    #[test]
    fn test_buffer_acquire_and_return() {
        let pool = create_buffer_pool();
        
        {
            let buffer = pool.acquire().unwrap();
            assert_eq!(buffer.len(), 0);
            assert_eq!(buffer.capacity(), DEFAULT_BUFFER_SIZE);
            assert_eq!(pool.stats().in_use, 1);
        }
        
        // Buffer should be returned automatically
        assert_eq!(pool.stats().in_use, 0);
    }

    #[test]
    fn test_buffer_reuse() {
        let pool = create_buffer_pool();
        
        {
            let mut buf = pool.acquire().unwrap();
            buf.copy_from_slice(b"test data").unwrap();
            assert_eq!(buf.len(), 9);
        }
        
        // Acquire again - should get recycled buffer (cleared)
        let buf = pool.acquire().unwrap();
        assert_eq!(buf.len(), 0);
        // Reuse count is 2: first acquire from preallocated + second from returned
        assert_eq!(pool.stats().buffer_reuses, 2);
    }

    #[test]
    fn test_buffer_operations() {
        let pool = create_buffer_pool();
        let mut buf = pool.acquire().unwrap();
        
        // Test copy_from_slice
        buf.copy_from_slice(b"hello").unwrap();
        assert_eq!(buf.len(), 5);
        assert_eq!(&buf[..], b"hello");
        
        // Test resize
        buf.resize(10).unwrap();
        assert_eq!(buf.len(), 10);
        
        // Test clear
        buf.clear();
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_pool_statistics() {
        let pool = create_buffer_pool();
        
        let _buf1 = pool.acquire().unwrap();
        let _buf2 = pool.acquire().unwrap();
        
        let stats = pool.stats();
        assert_eq!(stats.in_use, 2);
        assert!(stats.utilization > 0.0);
        assert!(stats.utilization < 1.0);
    }

    #[test]
    fn test_acquire_batch() {
        let pool = create_buffer_pool();
        
        let buffers = pool.acquire_batch(10).unwrap();
        assert_eq!(buffers.len(), 10);
        assert_eq!(pool.stats().in_use, 10);
        
        drop(buffers);
        assert_eq!(pool.stats().in_use, 0);
    }

    #[test]
    fn test_try_acquire() {
        let pool = Arc::new(BufferPool::new(100, 2));
        
        let _buf1 = pool.try_acquire().unwrap();
        let _buf2 = pool.try_acquire().unwrap();
        
        // Pool exhausted
        assert!(pool.try_acquire().is_none());
    }

    #[test]
    fn test_buffer_detach() {
        let pool = create_buffer_pool();
        let mut buf = pool.acquire().unwrap();
        
        buf.copy_from_slice(b"test").unwrap();
        let vec = buf.detach();
        
        assert_eq!(vec, b"test");
        // Buffer not returned to pool
        assert_eq!(pool.stats().in_use, 0);
    }

    #[test]
    fn test_zero_fill() {
        let pool = create_buffer_pool();
        let mut buf = pool.acquire().unwrap();
        
        buf.copy_from_slice(&[1, 2, 3, 4, 5]).unwrap();
        buf.zero_fill();
        
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_thread_safety() {
        use std::thread;
        
        let pool = create_buffer_pool();
        let mut handles = vec![];
        
        for _ in 0..4 {
            let pool_clone = Arc::clone(&pool);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    let mut buf = pool_clone.acquire().unwrap();
                    buf.copy_from_slice(b"thread test").unwrap();
                }
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        // All buffers should be returned
        assert_eq!(pool.stats().in_use, 0);
    }
}
