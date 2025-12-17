//! Buffer pooling for packet processing
//!
//! Specialized object pool for byte buffers (Vec<u8>) with pre-sized allocations.
//! Built on top of memory_pool for efficient packet buffer reuse.

use crate::memory_pool::{MemoryPool, PooledObject, Resettable};

/// Default buffer size for packet processing (MTU size)
pub const DEFAULT_BUFFER_SIZE: usize = 1500;

/// Default pool capacity
pub const DEFAULT_POOL_CAPACITY: usize = 8192;

/// Pooled byte buffer with pre-allocated capacity
pub type BufferPool = MemoryPool<Vec<u8>>;
pub type PooledBuffer = PooledObject<Vec<u8>>;

/// Creates a buffer pool with default MTU-sized buffers
pub fn create_buffer_pool() -> BufferPool {
    create_buffer_pool_with_size(DEFAULT_POOL_CAPACITY, DEFAULT_BUFFER_SIZE)
}

/// Creates buffer pool with custom capacity and buffer size
pub fn create_buffer_pool_with_size(capacity: usize, buffer_size: usize) -> BufferPool {
    MemoryPool::with_initializer(capacity, move || Vec::with_capacity(buffer_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_creation() {
        let pool = create_buffer_pool();
        let stats = pool.stats();
        assert_eq!(stats.capacity, DEFAULT_POOL_CAPACITY);
    }

    #[test]
    fn test_buffer_reuse() {
        let pool = create_buffer_pool();
        
        {
            let mut buf = pool.acquire().unwrap();
            buf.extend_from_slice(b"test data");
            assert!(!buf.is_empty());
        }
        
        // Buffer should be cleared on return
        let buf = pool.acquire().unwrap();
        assert!(buf.is_empty());
    }
}
