//! Byte buffer pooling for packet data and serialization
//!
//! Provides efficient byte buffer management with pre-allocated slabs,
//! per-thread caches, and zero-copy buffer views for high-throughput
//! packet processing.
//!
//! # Features
//! - **Fixed-Size Pools**: MTU (1500), jumbo (9000), small (256), large (64KB)
//! - **Variable-Size**: Power-of-two sizing with slab allocator
//! - **Per-Thread Caches**: Lock-free buffer allocation
//! - **Batch Operations**: Efficient batch acquire/release
//! - **Zero-Copy**: Buffer views and chains for scatter-gather I/O
//!
//! # Performance Features
//! - Pre-allocated buffer regions
//! - Lock-free per-thread caches
//! - Batch operations reduce contention
//! - Comprehensive statistics for monitoring

use crossbeam::queue::ArrayQueue;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ============================================================================
// Buffer Configuration
// ============================================================================

/// Default buffer sizes for different use cases
pub mod sizes {
    /// Small buffer for headers (256 bytes)
    pub const SMALL: usize = 256;
    /// Medium buffer for typical packets (1500 bytes MTU)
    pub const MEDIUM: usize = 1500;
    /// Large buffer for jumbo frames (9000 bytes)
    pub const LARGE: usize = 9000;
    /// Extra large buffer for aggregation (64KB)
    pub const XLARGE: usize = 65536;
}

// ============================================================================
// Buffer Pool
// ============================================================================

/// A pool of pre-allocated byte buffers
pub struct BufferPool {
    /// Pool of available buffers
    pool: ArrayQueue<Vec<u8>>,
    /// Size of each buffer
    buffer_size: usize,
    /// Statistics
    allocated: AtomicUsize,
    reused: AtomicUsize,
    returned: AtomicUsize,
}

impl BufferPool {
    /// Create a new buffer pool
    /// 
    /// # Arguments
    /// * `capacity` - Maximum number of buffers to pool
    /// * `buffer_size` - Size of each buffer
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        Self {
            pool: ArrayQueue::new(capacity),
            buffer_size,
            allocated: AtomicUsize::new(0),
            reused: AtomicUsize::new(0),
            returned: AtomicUsize::new(0),
        }
    }
    
    /// Create and pre-populate the pool
    pub fn with_preallocated(capacity: usize, buffer_size: usize, prefill: usize) -> Self {
        let pool = Self::new(capacity, buffer_size);
        pool.prefill(prefill);
        pool
    }
    
    /// Pre-fill the pool with buffers
    pub fn prefill(&self, count: usize) {
        for _ in 0..count {
            let buf = vec![0u8; self.buffer_size];
            self.allocated.fetch_add(1, Ordering::Relaxed);
            if self.pool.push(buf).is_err() {
                break;
            }
        }
    }
    
    /// Get a buffer from the pool
    pub fn get(&self) -> Vec<u8> {
        match self.pool.pop() {
            Some(buf) => {
                self.reused.fetch_add(1, Ordering::Relaxed);
                buf
            }
            None => {
                self.allocated.fetch_add(1, Ordering::Relaxed);
                vec![0u8; self.buffer_size]
            }
        }
    }
    
    /// Return a buffer to the pool
    pub fn put(&self, mut buf: Vec<u8>) {
        self.returned.fetch_add(1, Ordering::Relaxed);
        
        // Clear and potentially resize
        buf.clear();
        if buf.capacity() >= self.buffer_size {
            let _ = self.pool.push(buf);
        }
        // Otherwise drop it (wrong size)
    }
    
    /// Get buffer size
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
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
    
    /// Get statistics
    pub fn stats(&self) -> BufferPoolStats {
        BufferPoolStats {
            allocated: self.allocated.load(Ordering::Relaxed),
            reused: self.reused.load(Ordering::Relaxed),
            returned: self.returned.load(Ordering::Relaxed),
            pool_size: self.pool.len(),
        }
    }
}

/// Buffer pool statistics
#[derive(Debug, Clone, Default)]
pub struct BufferPoolStats {
    /// Total buffers allocated
    pub allocated: usize,
    /// Buffers reused from pool
    pub reused: usize,
    /// Buffers returned to pool
    pub returned: usize,
    /// Current pool size
    pub pool_size: usize,
}

impl BufferPoolStats {
    /// Calculate hit rate (reused / total acquired)
    pub fn hit_rate(&self) -> f64 {
        let total = self.allocated + self.reused;
        if total == 0 {
            0.0
        } else {
            (self.reused as f64) / (total as f64)
        }
    }
}

// ============================================================================
// Pooled Buffer Handle
// ============================================================================

/// A buffer that returns itself to the pool when dropped
pub struct PooledBuffer {
    buffer: Option<Vec<u8>>,
    pool: Arc<BufferPool>,
}

impl PooledBuffer {
    /// Get a buffer from the pool
    pub fn new(pool: Arc<BufferPool>) -> Self {
        Self {
            buffer: Some(pool.get()),
            pool,
        }
    }
    
    /// Take ownership of the buffer (won't return to pool)
    pub fn take(mut self) -> Vec<u8> {
        self.buffer.take().unwrap()
    }
    
    /// Get the buffer capacity
    pub fn capacity(&self) -> usize {
        self.buffer.as_ref().map(|b| b.capacity()).unwrap_or(0)
    }
}

impl Deref for PooledBuffer {
    type Target = Vec<u8>;
    
    fn deref(&self) -> &Self::Target {
        self.buffer.as_ref().unwrap()
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.as_mut().unwrap()
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(buf) = self.buffer.take() {
            self.pool.put(buf);
        }
    }
}

// ============================================================================
// Multi-Size Buffer Pool
// ============================================================================

/// Pool with multiple buffer sizes
pub struct MultiSizeBufferPool {
    small: BufferPool,
    medium: BufferPool,
    large: BufferPool,
    xlarge: BufferPool,
}

impl MultiSizeBufferPool {
    /// Create a new multi-size pool with default settings
    pub fn new() -> Self {
        Self {
            small: BufferPool::new(1000, sizes::SMALL),
            medium: BufferPool::new(500, sizes::MEDIUM),
            large: BufferPool::new(100, sizes::LARGE),
            xlarge: BufferPool::new(50, sizes::XLARGE),
        }
    }
    
    /// Create with custom sizes
    pub fn with_capacities(
        small_cap: usize,
        medium_cap: usize,
        large_cap: usize,
        xlarge_cap: usize,
    ) -> Self {
        Self {
            small: BufferPool::new(small_cap, sizes::SMALL),
            medium: BufferPool::new(medium_cap, sizes::MEDIUM),
            large: BufferPool::new(large_cap, sizes::LARGE),
            xlarge: BufferPool::new(xlarge_cap, sizes::XLARGE),
        }
    }
    
    /// Get a buffer of at least the requested size
    pub fn get(&self, min_size: usize) -> Vec<u8> {
        if min_size <= sizes::SMALL {
            self.small.get()
        } else if min_size <= sizes::MEDIUM {
            self.medium.get()
        } else if min_size <= sizes::LARGE {
            self.large.get()
        } else if min_size <= sizes::XLARGE {
            self.xlarge.get()
        } else {
            // Too large for pool
            vec![0u8; min_size]
        }
    }
    
    /// Return a buffer to the appropriate pool
    pub fn put(&self, buf: Vec<u8>) {
        let cap = buf.capacity();
        
        if cap <= sizes::SMALL {
            self.small.put(buf);
        } else if cap <= sizes::MEDIUM {
            self.medium.put(buf);
        } else if cap <= sizes::LARGE {
            self.large.put(buf);
        } else if cap <= sizes::XLARGE {
            self.xlarge.put(buf);
        }
        // Too large, just drop
    }
    
    /// Prefill all pools
    pub fn prefill(&self) {
        self.small.prefill(100);
        self.medium.prefill(50);
        self.large.prefill(20);
        self.xlarge.prefill(10);
    }
}

impl Default for MultiSizeBufferPool {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Power-of-Two Buffer Pool
// ============================================================================

/// Buffer pool using power-of-two size classes  
pub struct PowerOfTwoPool {
    pools: Vec<BufferPool>,
    min_shift: usize,  // Minimum size is 2^min_shift
}

impl PowerOfTwoPool {
    /// Create a new power-of-two pool
    /// 
    /// Sizes range from 2^min_shift to 2^max_shift
    pub fn new(min_shift: usize, max_shift: usize, capacity_per_size: usize) -> Self {
        let mut pools = Vec::new();
        
        for shift in min_shift..=max_shift {
            let size = 1 << shift;
            pools.push(BufferPool::new(capacity_per_size, size));
        }
        
        Self {
            pools,
            min_shift,
        }
    }
    
    /// Get buffer of at least the requested size
    pub fn get(&self, size: usize) -> Vec<u8> {
        let shift = self.size_to_shift(size);
        let index = shift.saturating_sub(self.min_shift);
        
        if index < self.pools.len() {
            self.pools[index].get()
        } else {
            // Too large - allocate directly
            vec![0u8; size]
        }
    }
    
    /// Return buffer to the pool
    pub fn put(&self, buf: Vec<u8>) {
        let cap = buf.capacity();
        if cap == 0 {
            return;
        }
        
        let shift = self.capacity_to_shift(cap);
        let index = shift.saturating_sub(self.min_shift);
        
        if index < self.pools.len() && (1 << shift) == cap {
            self.pools[index].put(buf);
        }
        // Otherwise just drop it
    }
    
    /// Convert size to shift value (rounds up)
    fn size_to_shift(&self, size: usize) -> usize {
        if size == 0 {
            return self.min_shift;
        }
        std::mem::size_of::<usize>() * 8 - (size - 1).leading_zeros() as usize
    }
    
    /// Convert capacity to shift value (exact)
    fn capacity_to_shift(&self, cap: usize) -> usize {
        if cap == 0 {
            return 0;
        }
        std::mem::size_of::<usize>() * 8 - cap.leading_zeros() as usize - 1
    }
}

// ============================================================================
// Per-Thread Buffer Cache
// ============================================================================

use std::cell::RefCell;

thread_local! {
    static THREAD_BUFFER_CACHE: RefCell<ThreadBufferCache> = RefCell::new(ThreadBufferCache::new());
}

/// Per-thread buffer cache for lock-free allocation
struct ThreadBufferCache {
    small: Vec<Vec<u8>>,
    medium: Vec<Vec<u8>>,
    large: Vec<Vec<u8>>,
    max_cached: usize,
}

impl ThreadBufferCache {
    fn new() -> Self {
        Self {
            small: Vec::new(),
            medium: Vec::new(),
            large: Vec::new(),
            max_cached: 16,  // Max buffers per size class
        }
    }
    
    fn get(&mut self, size: usize) -> Option<Vec<u8>> {
        let cache = if size <= sizes::SMALL {
            &mut self.small
        } else if size <= sizes::MEDIUM {
            &mut self.medium
        } else if size <= sizes::LARGE {
            &mut self.large
        } else {
            return None;
        };
        
        cache.pop()
    }
    
    fn put(&mut self, buf: Vec<u8>) {
        let cap = buf.capacity();
        let cache = if cap <= sizes::SMALL {
            &mut self.small
        } else if cap <= sizes::MEDIUM {
            &mut self.medium
        } else if cap <= sizes::LARGE {
            &mut self.large
        } else {
            return;  // Don't cache very large buffers
        };
        
        if cache.len() < self.max_cached {
            cache.push(buf);
        }
    }
}

/// Get a buffer from thread-local cache
pub fn get_thread_local_buffer(size: usize) -> Vec<u8> {
    THREAD_BUFFER_CACHE.with(|cache| {
        cache.borrow_mut().get(size)
    }).unwrap_or_else(|| vec![0u8; size])
}

/// Return buffer to thread-local cache
pub fn put_thread_local_buffer(buf: Vec<u8>) {
    THREAD_BUFFER_CACHE.with(|cache| {
        cache.borrow_mut().put(buf);
    });
}

// ============================================================================
// Batch Operations
// ============================================================================

impl BufferPool {
    /// Acquire multiple buffers at once
    pub fn get_batch(&self, count: usize) -> Vec<Vec<u8>> {
        let mut buffers = Vec::with_capacity(count);
        for _ in 0..count {
            buffers.push(self.get());
        }
        buffers
    }
    
    /// Return multiple buffers at once
    pub fn put_batch(&self, buffers: Vec<Vec<u8>>) {
        for buf in buffers {
            self.put(buf);
        }
    }
}

// ============================================================================
// Buffer View (Zero-Copy)
// ============================================================================

/// A view into a buffer without copying
#[derive(Debug)]
pub struct BufferView<'a> {
    data: &'a [u8],
    start: usize,
    end: usize,
}

impl<'a> BufferView<'a> {
    /// Create a new buffer view
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            start: 0,
            end: data.len(),
        }
    }
    
    /// Create a view of a slice
    pub fn slice(&self, start: usize, end: usize) -> Option<BufferView<'a>> {
        let abs_start = self.start + start;
        let abs_end = self.start + end;
        
        if abs_end <= self.end && abs_start <= abs_end {
            Some(BufferView {
                data: self.data,
                start: abs_start,
                end: abs_end,
            })
        } else {
            None
        }
    }
    
    /// Get the data
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.start..self.end]
    }
    
    /// Get length
    pub fn len(&self) -> usize {
        self.end - self.start
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
    
    /// Skip n bytes from the front
    pub fn skip(&mut self, n: usize) -> bool {
        if self.start + n <= self.end {
            self.start += n;
            true
        } else {
            false
        }
    }
    
    /// Take n bytes from the front
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.start + n <= self.end {
            let result = &self.data[self.start..self.start + n];
            self.start += n;
            Some(result)
        } else {
            None
        }
    }
    
    /// Read u8 from the front
    pub fn read_u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    
    /// Read u16 (big-endian) from the front
    pub fn read_u16_be(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    
    /// Read u32 (big-endian) from the front
    pub fn read_u32_be(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

impl<'a> Deref for BufferView<'a> {
    type Target = [u8];
    
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

// ============================================================================
// Buffer Chain
// ============================================================================

/// A chain of buffers for scatter-gather I/O
pub struct BufferChain {
    buffers: Vec<Vec<u8>>,
    total_len: usize,
}

impl BufferChain {
    /// Create a new empty chain
    pub fn new() -> Self {
        Self {
            buffers: Vec::new(),
            total_len: 0,
        }
    }
    
    /// Add a buffer to the chain
    pub fn push(&mut self, buf: Vec<u8>) {
        self.total_len += buf.len();
        self.buffers.push(buf);
    }
    
    /// Get total length
    pub fn len(&self) -> usize {
        self.total_len
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }
    
    /// Get number of buffers
    pub fn buffer_count(&self) -> usize {
        self.buffers.len()
    }
    
    /// Flatten to a single buffer
    pub fn flatten(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_len);
        for buf in &self.buffers {
            result.extend_from_slice(buf);
        }
        result
    }
    
    /// Get buffers as slices (for scatter-gather I/O)
    pub fn as_slices(&self) -> Vec<&[u8]> {
        self.buffers.iter().map(|b| b.as_slice()).collect()
    }
    
    /// Clear the chain
    pub fn clear(&mut self) {
        self.buffers.clear();
        self.total_len = 0;
    }
}

impl Default for BufferChain {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(10, 1024);
        
        let buf1 = pool.get();
        assert_eq!(buf1.capacity(), 1024);
        
        pool.put(buf1);
        assert_eq!(pool.len(), 1);
        
        let buf2 = pool.get();
        assert_eq!(pool.len(), 0);
        
        let stats = pool.stats();
        assert_eq!(stats.allocated, 1);
        assert_eq!(stats.reused, 1);
    }

    #[test]
    fn test_pooled_buffer() {
        let pool = Arc::new(BufferPool::new(10, 1024));
        
        {
            let mut buf = PooledBuffer::new(pool.clone());
            buf.extend_from_slice(b"hello");
            assert_eq!(&buf[..5], b"hello");
        } // Dropped here
        
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_multi_size_pool() {
        let pool = MultiSizeBufferPool::new();
        
        let small = pool.get(100);
        assert!(small.capacity() >= 100);
        
        let medium = pool.get(1000);
        assert!(medium.capacity() >= 1000);
        
        pool.put(small);
        pool.put(medium);
    }

    #[test]
    fn test_buffer_view() {
        let data = b"hello world";
        let mut view = BufferView::new(data);
        
        assert_eq!(view.len(), 11);
        
        let hello = view.take(5).unwrap();
        assert_eq!(hello, b"hello");
        
        view.skip(1); // Skip space
        
        assert_eq!(view.as_slice(), b"world");
    }

    #[test]
    fn test_buffer_view_read() {
        let data = [0x00, 0x50, 0x00, 0x00, 0x00, 0x01];
        let mut view = BufferView::new(&data);
        
        assert_eq!(view.read_u16_be(), Some(80)); // Port 80
        assert_eq!(view.read_u32_be(), Some(1));
    }

    #[test]
    fn test_buffer_chain() {
        let mut chain = BufferChain::new();
        
        chain.push(b"hello ".to_vec());
        chain.push(b"world".to_vec());
        
        assert_eq!(chain.len(), 11);
        assert_eq!(chain.buffer_count(), 2);
        assert_eq!(chain.flatten(), b"hello world");
    }

    #[test]
    fn test_buffer_pool_stats() {
        let pool = BufferPool::new(10, 1024);
        
        let _buf1 = pool.get();
        let _buf2 = pool.get();
        pool.put(_buf1);
        let _buf3 = pool.get();  // Should reuse
        
        let stats = pool.stats();
        assert_eq!(stats.allocated, 2);
        assert_eq!(stats.reused, 1);
        assert!(stats.hit_rate() > 0.0);
    }

    #[test]
    fn test_power_of_two_pool() {
        let pool = PowerOfTwoPool::new(6, 12, 10);  // 64 bytes to 4096 bytes
        
        let buf = pool.get(100);
        assert!(buf.capacity() >= 100);
        assert!(buf.capacity().is_power_of_two());
        
        pool.put(buf);
    }

    #[test]
    fn test_thread_local_cache() {
        let buf = get_thread_local_buffer(256);
        assert!(buf.capacity() >= 256);
        
        put_thread_local_buffer(buf);
        
        // Next get should reuse
        let buf2 = get_thread_local_buffer(256);
        assert!(buf2.capacity() >= 256);
    }

    #[test]
    fn test_batch_operations() {
        let pool = BufferPool::new(100, 1024);
        
        let buffers = pool.get_batch(10);
        assert_eq!(buffers.len(), 10);
        
        pool.put_batch(buffers);
        assert_eq!(pool.len(), 10);
    }

    #[test]
    fn test_buffer_view_slice() {
        let data = b"hello world";
        let view = BufferView::new(data);
        
        let hello_view = view.slice(0, 5).unwrap();
        assert_eq!(hello_view.as_slice(), b"hello");
        
        let world_view = view.slice(6, 11).unwrap();
        assert_eq!(world_view.as_slice(), b"world");
    }
}
