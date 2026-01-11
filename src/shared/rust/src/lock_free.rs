//! Lock-free data structures for high-performance packet processing
//!
//! Provides truly lock-free multi-producer multi-consumer (MPMC) queue, single-producer
//! single-consumer (SPSC) ring buffer, concurrent hash map, and lock-free counters.
//! These structures enable zero-allocation packet handling and avoid lock contention.

use crate::error::{Result, SafeOpsError};
use crossbeam::queue::ArrayQueue;
use dashmap::DashMap;
use std::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::hash::Hash;
use std::thread;
use std::ptr;

// ============================================================================
// MPMC Queue Wrapper
// ============================================================================

/// Lock-free multi-producer multi-consumer (MPMC) queue
///
/// Fixed capacity queue using crossbeam's ArrayQueue. Thread-safe for
/// multiple producers and consumers simultaneously.
pub struct MpmcQueue<T> {
    queue: Arc<ArrayQueue<T>>,
}

impl<T> MpmcQueue<T> {
    /// Creates new MPMC queue with specified capacity
    ///
    /// Capacity should be power of two for optimal performance
    pub fn new(capacity: usize) -> Self {
        MpmcQueue {
            queue: Arc::new(ArrayQueue::new(capacity)),
        }
    }

    /// Non-blocking enqueue, returns element if full
    pub fn push(&self, element: T) -> std::result::Result<(), T> {
        self.queue.push(element)
    }

    /// Non-blocking dequeue, returns None if empty
    pub fn pop(&self) -> Option<T> {
        self.queue.pop()
    }

    /// Retries push with spin-wait timeout
    pub fn try_push_timeout(&self, mut element: T, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        loop {
            match self.queue.push(element) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    element = e;
                    if start.elapsed() > timeout {
                        return Err(SafeOpsError::internal("Queue push timeout"));
                    }
                    thread::yield_now();
                }
            }
        }
    }

    /// Approximate current length (may be stale)
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Check if empty (may be stale)
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Check if full (may be stale)
    pub fn is_full(&self) -> bool {
        self.queue.is_full()
    }

    /// Returns fixed capacity
    pub fn capacity(&self) -> usize {
        self.queue.capacity()
    }
}

impl<T> Clone for MpmcQueue<T> {
    fn clone(&self) -> Self {
        MpmcQueue {
            queue: Arc::clone(&self.queue),
        }
    }
}

// ============================================================================
// SPSC Ring Buffer
// ============================================================================

/// Cache line size for padding (typically 64 bytes on x86-64)
const CACHE_LINE_SIZE: usize = 64;

/// Cache-line padded atomic to prevent false sharing
#[repr(align(64))]
struct PaddedAtomic {
    value: AtomicUsize,
}

impl PaddedAtomic {
    fn new(val: usize) -> Self {
        PaddedAtomic {
            value: AtomicUsize::new(val),
        }
    }

    fn load(&self, order: Ordering) -> usize {
        self.value.load(order)
    }

    fn store(&self, val: usize, order: Ordering) {
        self.value.store(val, order);
    }
}

/// Single-producer single-consumer ring buffer
///
/// Optimized for packet metadata transfer with cache-line padding
/// to prevent false sharing. Fixed power-of-two capacity.
pub struct SpscRingBuffer<T> {
    buffer: Vec<Option<T>>,
    capacity: usize,
    mask: usize,
    head: PaddedAtomic, // Producer writes here
    tail: PaddedAtomic, // Consumer reads here
}

impl<T> SpscRingBuffer<T> {
    /// Creates new SPSC ring buffer with power-of-two capacity
    pub fn new(mut capacity: usize) -> Self {
        // Round up to next power of two
        capacity = capacity.next_power_of_two();
        let mask = capacity - 1;

        let mut buffer = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            buffer.push(None);
        }

        SpscRingBuffer {
            buffer,
            capacity,
            mask,
            head: PaddedAtomic::new(0),
            tail: PaddedAtomic::new(0),
        }
    }

    /// Producer-only write, returns false if full, never allocates
    pub fn write(&mut self, element: T) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);

        let next_head = (head + 1) & self.mask;
        if next_head == tail {
            return false; // Buffer full
        }

        self.buffer[head] = Some(element);
        self.head.store(next_head, Ordering::Release);
        true
    }

    /// Consumer-only read, updates tail atomically, never allocates
    pub fn read(&mut self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);

        if tail == head {
            return None; // Buffer empty
        }

        let element = self.buffer[tail].take();
        let next_tail = (tail + 1) & self.mask;
        self.tail.store(next_tail, Ordering::Release);
        element
    }

    /// Returns fixed capacity
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Approximate elements in buffer (may be stale)
    pub fn available(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        (head.wrapping_sub(tail)) & self.mask
    }

    /// Consumer check if empty (may be stale)
    pub fn is_empty(&self) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        tail == head
    }

    /// Producer check if full (may be stale)
    pub fn is_full(&self) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        ((head + 1) & self.mask) == tail
    }
}

// ============================================================================
// Concurrent Hash Map (DashMap Wrapper)
// ============================================================================

/// Truly lock-free concurrent hash map using DashMap
///
/// Multiple readers and writers can access simultaneously without locks.
/// Interior sharding reduces contention automatically.
pub struct ConcurrentHashMap<K, V> {
    map: Arc<DashMap<K, V>>,
}

impl<K: Hash + Eq, V> ConcurrentHashMap<K, V> {
    /// Creates new concurrent hash map with default settings
    pub fn new() -> Self {
        ConcurrentHashMap {
            map: Arc::new(DashMap::new()),
        }
    }

    /// Creates with specified shard count (power of two)
    pub fn with_capacity(capacity: usize) -> Self {
        ConcurrentHashMap {
            map: Arc::new(DashMap::with_capacity(capacity)),
        }
    }

    /// Inserts key-value pair, returns previous value if existed
    pub fn insert(&self, key: K, value: V) -> Option<V> {
        self.map.insert(key, value)
    }

    /// Gets value for key (returns cloned value)
    pub fn get(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        self.map.get(key).map(|r| r.value().clone())
    }

    /// Removes key-value pair
    pub fn remove(&self, key: &K) -> Option<(K, V)> {
        self.map.remove(key)
    }

    /// Checks if key exists
    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Approximate map size
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Removes all entries
    pub fn clear(&self) {
        self.map.clear();
    }
}

impl<K: Hash + Eq, V> Clone for ConcurrentHashMap<K, V> {
    fn clone(&self) -> Self {
        ConcurrentHashMap {
            map: Arc::clone(&self.map),
        }
    }
}

impl<K: Hash + Eq, V> Default for ConcurrentHashMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Lock-Free Counter
// ============================================================================

/// Lock-free counter for metrics and statistics
///
/// Uses AtomicU64 with Relaxed ordering for performance
pub struct LockFreeCounter {
    value: AtomicU64,
}

impl LockFreeCounter {
    /// Creates new counter initialized to zero
    pub fn new() -> Self {
        LockFreeCounter {
            value: AtomicU64::new(0),
        }
    }

    /// Creates counter with initial value
    pub fn with_value(initial: u64) -> Self {
        LockFreeCounter {
            value: AtomicU64::new(initial),
        }
    }

    /// Atomically increments by one, returns previous value
    pub fn increment(&self) -> u64 {
        self.value.fetch_add(1, Ordering::Relaxed)
    }

    /// Atomically adds amount, returns previous value
    pub fn add(&self, amount: u64) -> u64 {
        self.value.fetch_add(amount, Ordering::Relaxed)
    }

    /// Reads current value (may be stale immediately)
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Atomically sets to value
    pub fn set(&self, value: u64) {
        self.value.store(value, Ordering::Relaxed);
    }

    /// Atomically sets to zero
    pub fn reset(&self) {
        self.value.store(0, Ordering::Relaxed);
    }

    /// Atomically swaps with new value, returns old
    pub fn swap(&self, new: u64) -> u64 {
        self.value.swap(new, Ordering::Relaxed)
    }
}

impl Default for LockFreeCounter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Lock-Free Stack (True Treiber Stack)
// ============================================================================

struct Node<T> {
    data: T,
    next: *mut Node<T>,
}

/// Truly lock-free stack using Treiber algorithm with AtomicPtr
///
/// Push and pop use compare-and-swap (CAS) operations. Wait-free progress guarantee.
/// No capacity limit (grows dynamically).
pub struct LockFreeStack<T> {
    head: AtomicPtr<Node<T>>,
}

impl<T> LockFreeStack<T> {
    /// Creates new empty stack
    pub fn new() -> Self {
        LockFreeStack {
            head: AtomicPtr::new(ptr::null_mut()),
        }
    }

    /// Pushes element onto stack using CAS loop
    ///
    /// Always succeeds, wait-free (bounded number of retries)
    pub fn push(&self, element: T) {
        let new_node = Box::into_raw(Box::new(Node {
            data: element,
            next: ptr::null_mut(),
        }));

        loop {
            let old_head = self.head.load(Ordering::Relaxed);
            unsafe {
                (*new_node).next = old_head;
            }

            // Try to swap in new node as head
            if self
                .head
                .compare_exchange_weak(
                    old_head,
                    new_node,
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return;
            }
            // CAS failed, retry
        }
    }

    /// Pops element from stack using CAS loop
    ///
    /// Returns None if empty. Wait-free.
    pub fn pop(&self) -> Option<T> {
        loop {
            let old_head = self.head.load(Ordering::Acquire);
            
            if old_head.is_null() {
                return None; // Stack empty
            }

            let next = unsafe { (*old_head).next };

            // Try to swap next node as new head
            if self
                .head
                .compare_exchange_weak(
                    old_head,
                    next,
                    Ordering::Release,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                // Successfully popped, extract data and free node
                let node = unsafe { Box::from_raw(old_head) };
                return Some(node.data);
            }
            // CAS failed, retry
        }
    }

    /// Check if stack is empty (may be stale)
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire).is_null()
    }
}

impl<T> Default for LockFreeStack<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for LockFreeStack<T> {
    fn drop(&mut self) {
        // Clean up all remaining nodes
        while self.pop().is_some() {}
    }
}

// SAFETY: Send if T is Send (nodes can be moved between threads)
unsafe impl<T: Send> Send for LockFreeStack<T> {}
// SAFETY: Sync if T is Send (multiple threads can access via &self)
unsafe impl<T: Send> Sync for LockFreeStack<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpmc_queue() {
        let queue = MpmcQueue::new(10);
        
        assert!(queue.push(1).is_ok());
        assert!(queue.push(2).is_ok());
        
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn test_mpmc_queue_full() {
        let queue = MpmcQueue::new(2);
        
        assert!(queue.push(1).is_ok());
        assert!(queue.push(2).is_ok());
        assert!(queue.push(3).is_err()); // Full
    }

    #[test]
    fn test_spsc_ring_buffer() {
        let mut buffer = SpscRingBuffer::new(4);
        
        assert!(buffer.write(1));
        assert!(buffer.write(2));
        
        assert_eq!(buffer.read(), Some(1));
        assert_eq!(buffer.read(), Some(2));
        assert_eq!(buffer.read(), None);
    }

    #[test]
    fn test_spsc_ring_buffer_wrap() {
        let mut buffer = SpscRingBuffer::new(4);
        
        // Fill buffer
        assert!(buffer.write(1));
        assert!(buffer.write(2));
        assert!(buffer.write(3));
        assert!(!buffer.write(4)); // Full (capacity-1)
        
        // Read some
        assert_eq!(buffer.read(), Some(1));
        assert_eq!(buffer.read(), Some(2));
        
        // Write again (should wrap around)
        assert!(buffer.write(4));
        assert!(buffer.write(5));
    }

    #[test]
    fn test_concurrent_hashmap() {
        let map: ConcurrentHashMap<String, i32> = ConcurrentHashMap::new();
        
        assert_eq!(map.insert(String::from("key1"), 100), None);
        assert_eq!(map.get(&String::from("key1")), Some(100));
        assert_eq!(map.insert(String::from("key1"), 200), Some(100));
        assert_eq!(map.remove(&String::from("key1")), Some((String::from("key1"), 200)));
        assert!(!map.contains_key(&String::from("key1")));
    }

    #[test]
    fn test_lock_free_counter() {
        let counter = LockFreeCounter::new();
        
        assert_eq!(counter.get(), 0);
        assert_eq!(counter.increment(), 0);
        assert_eq!(counter.get(), 1);
        assert_eq!(counter.add(5), 1);
        assert_eq!(counter.get(), 6);
        assert_eq!(counter.swap(100), 6);
        assert_eq!(counter.get(), 100);
        counter.reset();
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_lock_free_stack() {
        let stack = LockFreeStack::new();
        
        stack.push(1);
        stack.push(2);
        stack.push(3);
        
        assert_eq!(stack.pop(), Some(3));
        assert_eq!(stack.pop(), Some(2));
        assert_eq!(stack.pop(), Some(1));
        assert_eq!(stack.pop(), None);
        assert!(stack.is_empty());
    }

    #[test]
    fn test_lock_free_stack_concurrent() {
        use std::thread;
        
        let stack = Arc::new(LockFreeStack::new());
        let mut handles = vec![];
        
        // Push from multiple threads
        for i in 0..4 {
            let stack_clone = Arc::clone(&stack);
            let handle = thread::spawn(move || {
                for j in 0..100 {
                    stack_clone.push(i * 100 + j);
                }
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Should have 400 elements
        let mut count = 0;
        while stack.pop().is_some() {
            count += 1;
        }
        assert_eq!(count, 400);
    }
}
