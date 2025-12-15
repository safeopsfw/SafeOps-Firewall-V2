//! Lock-free data structures for high-concurrency scenarios
//!
//! Provides high-performance concurrent data structures optimized for
//! multi-threaded packet processing with zero lock contention.
//!
//! # Data Structures
//! - **Lock-Free Queue**: MPMC (multi-producer multi-consumer) bounded/unbounded
//! - **SPSC Queue**: Single-producer single-consumer for zero-contention scenarios
//! - **Lock-Free Stack**: LIFO with ABA problem prevention
//! - **Concurrent Map**: Lock-based concurrent hash map (see dashmap for true lock-free)
//! - **Ring Buffer**: Fixed-size circular buffer for streaming
//!
//! # Performance Characteristics
//! - Zero lock contention for wait-free operations
//! - Cache-line aligned structures to prevent false sharing
//! - Explicit memory ordering for optimal performance
//! - ABA problem prevention in stack operations
//!
//! # Atomic Operations
//! - Compare-and-swap (CAS) primitives
//! - Memory barriers (acquire/release/seq_cst)
//! - Fetch-and-add/sub operations
//! - Load/store with explicit ordering

use crossbeam::channel::{bounded, unbounded, Receiver, Sender, TryRecvError, TrySendError};
use crossbeam::epoch::{self, Atomic, Owned};
use crossbeam::queue::{ArrayQueue, SegQueue};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::hash::Hash;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

// ============================================================================
// Cache-Line Alignment Constants
// ============================================================================

/// Cache line size for x86/x64 processors
const CACHE_LINE_SIZE: usize = 64;

/// Cache-line aligned wrapper to prevent false sharing
#[repr(align(64))]
pub struct CacheAligned<T>(pub T);

// ============================================================================
// Lock-Free Queue
// ============================================================================

/// A lock-free bounded MPMC queue
pub struct LockFreeQueue<T> {
    inner: ArrayQueue<T>,
    push_count: AtomicU64,
    pop_count: AtomicU64,
}

impl<T> LockFreeQueue<T> {
    /// Create a new queue with the given capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: ArrayQueue::new(capacity),
            push_count: AtomicU64::new(0),
            pop_count: AtomicU64::new(0),
        }
    }
    
    /// Push an item to the queue
    /// 
    /// Returns `Err(item)` if the queue is full.
    pub fn push(&self, item: T) -> Result<(), T> {
        match self.inner.push(item) {
            Ok(()) => {
                self.push_count.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(item) => Err(item),
        }
    }
    
    /// Pop an item from the queue
    pub fn pop(&self) -> Option<T> {
        self.inner.pop().map(|item| {
            self.pop_count.fetch_add(1, Ordering::Relaxed);
            item
        })
    }
    
    /// Check if the queue is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    
    /// Check if the queue is full
    pub fn is_full(&self) -> bool {
        self.inner.is_full()
    }
    
    /// Get the current length
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    
    /// Get the capacity
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }
    
    /// Get total push count
    pub fn push_count(&self) -> u64 {
        self.push_count.load(Ordering::Relaxed)
    }
    
    /// Get total pop count
    pub fn pop_count(&self) -> u64 {
        self.pop_count.load(Ordering::Relaxed)
    }
}

// ============================================================================
// Unbounded Lock-Free Queue
// ============================================================================

/// An unbounded lock-free MPMC queue
pub struct UnboundedQueue<T> {
    inner: SegQueue<T>,
    count: AtomicUsize,
}

impl<T> UnboundedQueue<T> {
    /// Create a new unbounded queue
    pub fn new() -> Self {
        Self {
            inner: SegQueue::new(),
            count: AtomicUsize::new(0),
        }
    }
    
    /// Push an item to the queue
    pub fn push(&self, item: T) {
        self.inner.push(item);
        self.count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Pop an item from the queue
    pub fn pop(&self) -> Option<T> {
        self.inner.pop().map(|item| {
            self.count.fetch_sub(1, Ordering::Relaxed);
            item
        })
    }
    
    /// Check if the queue is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    
    /// Get approximate length
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }
}

impl<T> Default for UnboundedQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SPSC Queue (Single Producer, Single Consumer)
// ============================================================================

/// A wait-free SPSC queue for zero-contention scenarios
///
/// This is optimized for single-threaded producer and consumer.
/// Much faster than MPMC when you have dedicated threads.
#[repr(align(64))]  // Cache-line aligned to prevent false sharing
pub struct SpscQueue<T> {
    buffer: Vec<Option<T>>,
    capacity: usize,
    // These are on separate cache lines
    head: CacheAligned<AtomicUsize>,
    tail: CacheAligned<AtomicUsize>,
}

impl<T> SpscQueue<T> {
    /// Create a new SPSC queue with the given capacity
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two();
        Self {
            buffer: (0..capacity).map(|_| None).collect(),
            capacity,
            head: CacheAligned(AtomicUsize::new(0)),
            tail: CacheAligned(AtomicUsize::new(0)),
        }
    }
    
    /// Push an item (producer side - wait-free)
    pub fn push(&mut self, item: T) -> Result<(), T> {
        let tail = self.tail.0.load(Ordering::Relaxed);
        let head = self.head.0.load(Ordering::Acquire);
        
        let next_tail = tail.wrapping_add(1);
        if next_tail.wrapping_sub(head) > self.capacity {
            return Err(item);
        }
        
        let idx = tail & (self.capacity - 1);
        self.buffer[idx] = Some(item);
        self.tail.0.store(next_tail, Ordering::Release);
        Ok(())
    }
    
    /// Pop an item (consumer side - wait-free)
    pub fn pop(&mut self) -> Option<T> {
        let head = self.head.0.load(Ordering::Relaxed);
        let tail = self.tail.0.load(Ordering::Acquire);
        
        if head == tail {
            return None;
        }
        
        let idx = head & (self.capacity - 1);
        let item = self.buffer[idx].take();
        self.head.0.store(head.wrapping_add(1), Ordering::Release);
        item
    }
    
    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        let head = self.head.0.load(Ordering::Relaxed);
        let tail = self.tail.0.load(Ordering::Relaxed);
        head == tail
    }
    
    /// Get queue length (approximate)
    pub fn len(&self) -> usize {
        let head = self.head.0.load(Ordering::Relaxed);
        let tail = self.tail.0.load(Ordering::Relaxed);
        tail.wrapping_sub(head)
    }
    
    /// Get capacity
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

// ============================================================================
// Lock-Free Stack
// ============================================================================

struct StackNode<T> {
    data: T,
    next: Atomic<StackNode<T>>,
}

/// A lock-free stack (LIFO) with ABA problem prevention
///
/// Uses epoch-based reclamation to safely manage memory.
pub struct LockFreeStack<T> {
    head: Atomic<StackNode<T>>,
}

impl<T> LockFreeStack<T> {
    /// Create a new empty stack
    pub fn new() -> Self {
        Self {
            head: Atomic::null(),
        }
    }
    
    /// Push an item onto the stack
    pub fn push(&self, data: T) {
        let guard = epoch::pin();
        
        let new_node = Owned::new(StackNode {
            data,
            next: Atomic::null(),
        });
        
        let new_node = new_node.into_shared(&guard);
        
        loop {
            let head = self.head.load(Ordering::Acquire, &guard);
            unsafe {
                new_node.deref().next.store(head, Ordering::Relaxed);
            }
            
            if self.head
                .compare_exchange(
                    head,
                    new_node,
                    Ordering::Release,
                    Ordering::Acquire,
                    &guard,
                )
                .is_ok()
            {
                break;
            }
        }
    }
    
    /// Pop an item from the stack
    pub fn pop(&self) -> Option<T> {
        let guard = epoch::pin();
        
        loop {
            let head = self.head.load(Ordering::Acquire, &guard);
            
            if head.is_null() {
                return None;
            }
            
            let next = unsafe { head.deref().next.load(Ordering::Acquire, &guard) };
            
            if self.head
                .compare_exchange(
                    head,
                    next,
                    Ordering::Release,
                    Ordering::Acquire,
                    &guard,
                )
                .is_ok()
            {
                unsafe {
                    // Move data out before deferring destruction
                    let data = ptr::read(&head.deref().data);
                    guard.defer_destroy(head);
                    return Some(data);
                }
            }
        }
    }
    
    /// Check if stack is empty
    pub fn is_empty(&self) -> bool {
        let guard = epoch::pin();
        self.head.load(Ordering::Acquire, &guard).is_null()
    }
}

impl<T> Default for LockFreeStack<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for LockFreeStack<T> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}

// ============================================================================
// Atomic Operation Utilities
// ============================================================================

/// Atomic operations with explicit memory ordering
pub struct AtomicOps;

impl AtomicOps {
    /// Compare-and-swap with sequential consistency
    #[inline]
    pub fn cas_u64(atomic: &AtomicU64, current: u64, new: u64) -> Result<u64, u64> {
        atomic.compare_exchange(
            current,
            new,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
    }
    
    /// Compare-and-swap with acquire-release ordering
    #[inline]
    pub fn cas_u64_acqrel(atomic: &AtomicU64, current: u64, new: u64) -> Result<u64, u64> {
        atomic.compare_exchange(
            current,
            new,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
    }
    
    /// Load with acquire ordering
    #[inline]
    pub fn load_acquire(atomic: &AtomicU64) -> u64 {
        atomic.load(Ordering::Acquire)
    }
    
    /// Store with release ordering
    #[inline]
    pub fn store_release(atomic: &AtomicU64, value: u64) {
        atomic.store(value, Ordering::Release);
    }
    
    /// Fetch-and-add with relaxed ordering
    #[inline]
    pub fn fetch_add_relaxed(atomic: &AtomicU64, value: u64) -> u64 {
        atomic.fetch_add(value, Ordering::Relaxed)
    }
    
    /// Fetch-and-sub with relaxed ordering
    #[inline]
    pub fn fetch_sub_relaxed(atomic: &AtomicU64, value: u64) -> u64 {
        atomic.fetch_sub(value, Ordering::Relaxed)
    }
    
    /// Full memory barrier (fence)
    #[inline]
    pub fn fence_seqcst() {
        std::sync::atomic::fence(Ordering::SeqCst);
    }
    
    /// Acquire fence
    #[inline]
    pub fn fence_acquire() {
        std::sync::atomic::fence(Ordering::Acquire);
    }
    
    /// Release fence
    #[inline]
    pub fn fence_release() {
        std::sync::atomic::fence(Ordering::Release);
    }
}

// ============================================================================
// MPSC Channel (Multiple Producer, Single Consumer)
// ============================================================================

/// MPSC channel wrapper with metrics
pub struct MpscChannel<T> {
    sender: Sender<T>,
    receiver: Receiver<T>,
    sent: AtomicU64,
    received: AtomicU64,
}

impl<T> MpscChannel<T> {
    /// Create a bounded channel
    pub fn bounded(capacity: usize) -> Self {
        let (sender, receiver) = bounded(capacity);
        Self {
            sender,
            receiver,
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
        }
    }
    
    /// Create an unbounded channel
    pub fn unbounded() -> Self {
        let (sender, receiver) = unbounded();
        Self {
            sender,
            receiver,
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
        }
    }
    
    /// Get a cloneable sender
    pub fn sender(&self) -> Sender<T> {
        self.sender.clone()
    }
    
    /// Send an item (blocking)
    pub fn send(&self, item: T) -> Result<(), crossbeam::channel::SendError<T>> {
        self.sender.send(item).map(|()| {
            self.sent.fetch_add(1, Ordering::Relaxed);
        })
    }
    
    /// Try to send an item (non-blocking)
    pub fn try_send(&self, item: T) -> Result<(), TrySendError<T>> {
        self.sender.try_send(item).map(|()| {
            self.sent.fetch_add(1, Ordering::Relaxed);
        })
    }
    
    /// Receive an item (blocking)
    pub fn recv(&self) -> Result<T, crossbeam::channel::RecvError> {
        self.receiver.recv().map(|item| {
            self.received.fetch_add(1, Ordering::Relaxed);
            item
        })
    }
    
    /// Try to receive an item (non-blocking)
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        self.receiver.try_recv().map(|item| {
            self.received.fetch_add(1, Ordering::Relaxed);
            item
        })
    }
    
    /// Get the number of items sent
    pub fn sent_count(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
    
    /// Get the number of items received
    pub fn received_count(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }
}

// ============================================================================
// Concurrent HashMap Wrapper
// ============================================================================

/// A thread-safe HashMap with RwLock
/// 
/// For higher concurrency, consider using dashmap crate.
pub struct ConcurrentMap<K, V> {
    inner: RwLock<HashMap<K, V>>,
}

impl<K: Eq + Hash, V> ConcurrentMap<K, V> {
    /// Create a new concurrent map
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }
    
    /// Create with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::with_capacity(capacity)),
        }
    }
    
    /// Insert a key-value pair
    pub fn insert(&self, key: K, value: V) -> Option<V> {
        self.inner.write().insert(key, value)
    }
    
    /// Get a value by key (cloning)
    pub fn get(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        self.inner.read().get(key).cloned()
    }
    
    /// Remove a key
    pub fn remove(&self, key: &K) -> Option<V> {
        self.inner.write().remove(key)
    }
    
    /// Check if key exists
    pub fn contains_key(&self, key: &K) -> bool {
        self.inner.read().contains_key(key)
    }
    
    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
    
    /// Clear all entries
    pub fn clear(&self) {
        self.inner.write().clear();
    }
    
    /// Get all keys (cloning)
    pub fn keys(&self) -> Vec<K>
    where
        K: Clone,
    {
        self.inner.read().keys().cloned().collect()
    }
}

impl<K: Eq + Hash, V> Default for ConcurrentMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Atomic Counter
// ============================================================================

/// A thread-safe counter with various atomic operations
#[derive(Default)]
pub struct AtomicCounter {
    value: AtomicU64,
}

impl AtomicCounter {
    /// Create a new counter initialized to 0
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }
    
    /// Create with initial value
    pub fn with_value(value: u64) -> Self {
        Self {
            value: AtomicU64::new(value),
        }
    }
    
    /// Increment and return new value
    pub fn increment(&self) -> u64 {
        self.value.fetch_add(1, Ordering::Relaxed) + 1
    }
    
    /// Decrement and return new value
    pub fn decrement(&self) -> u64 {
        self.value.fetch_sub(1, Ordering::Relaxed) - 1
    }
    
    /// Add a value and return new total
    pub fn add(&self, n: u64) -> u64 {
        self.value.fetch_add(n, Ordering::Relaxed) + n
    }
    
    /// Get current value
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
    
    /// Set value
    pub fn set(&self, value: u64) {
        self.value.store(value, Ordering::Relaxed);
    }
    
    /// Reset to 0 and return old value
    pub fn reset(&self) -> u64 {
        self.value.swap(0, Ordering::Relaxed)
    }
    
    /// Compare and swap
    pub fn compare_and_swap(&self, current: u64, new: u64) -> bool {
        self.value
            .compare_exchange(current, new, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
    }
}

// ============================================================================
// Ring Buffer (Lock-Free)
// ============================================================================

/// A fixed-size ring buffer for streaming data
pub struct RingBuffer<T> {
    buffer: Vec<Option<T>>,
    head: AtomicUsize,
    tail: AtomicUsize,
    capacity: usize,
}

impl<T: Clone> RingBuffer<T> {
    /// Create a new ring buffer with the given capacity
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two();
        Self {
            buffer: (0..capacity).map(|_| None).collect(),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            capacity,
        }
    }
    
    /// Push an item, overwriting oldest if full
    pub fn push(&mut self, item: T) {
        let tail = self.tail.load(Ordering::Relaxed);
        let idx = tail & (self.capacity - 1);
        
        self.buffer[idx] = Some(item);
        self.tail.store(tail.wrapping_add(1), Ordering::Relaxed);
        
        // If we've wrapped around past head, move head forward
        let head = self.head.load(Ordering::Relaxed);
        if tail.wrapping_sub(head) >= self.capacity {
            self.head.store(head.wrapping_add(1), Ordering::Relaxed);
        }
    }
    
    /// Pop the oldest item
    pub fn pop(&mut self) -> Option<T> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        
        if head == tail {
            return None;
        }
        
        let idx = head & (self.capacity - 1);
        let item = self.buffer[idx].take();
        self.head.store(head.wrapping_add(1), Ordering::Relaxed);
        item
    }
    
    /// Get the number of items
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        tail.wrapping_sub(head).min(self.capacity)
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Relaxed) == self.tail.load(Ordering::Relaxed)
    }
    
    /// Get capacity
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_lock_free_queue() {
        let queue = LockFreeQueue::new(10);
        
        queue.push(1).unwrap();
        queue.push(2).unwrap();
        
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn test_unbounded_queue() {
        let queue = UnboundedQueue::new();
        
        for i in 0..100 {
            queue.push(i);
        }
        
        assert_eq!(queue.len(), 100);
        
        for i in 0..100 {
            assert_eq!(queue.pop(), Some(i));
        }
    }

    #[test]
    fn test_mpsc_channel() {
        let channel = MpscChannel::bounded(10);
        
        channel.send(42).unwrap();
        assert_eq!(channel.recv().unwrap(), 42);
        
        assert_eq!(channel.sent_count(), 1);
        assert_eq!(channel.received_count(), 1);
    }

    #[test]
    fn test_concurrent_map() {
        let map = ConcurrentMap::new();
        
        map.insert("key1", 1);
        map.insert("key2", 2);
        
        assert_eq!(map.get(&"key1"), Some(1));
        assert_eq!(map.get(&"key2"), Some(2));
        assert_eq!(map.get(&"key3"), None);
        
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_atomic_counter() {
        let counter = AtomicCounter::new();
        
        assert_eq!(counter.increment(), 1);
        assert_eq!(counter.increment(), 2);
        assert_eq!(counter.add(10), 12);
        assert_eq!(counter.decrement(), 11);
        assert_eq!(counter.get(), 11);
        assert_eq!(counter.reset(), 11);
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_ring_buffer() {
        let mut rb = RingBuffer::new(4);
        
        rb.push(1);
        rb.push(2);
        rb.push(3);
        
        assert_eq!(rb.len(), 3);
        assert_eq!(rb.pop(), Some(1));
        assert_eq!(rb.pop(), Some(2));
        
        // Push more to trigger wrap
        rb.push(4);
        rb.push(5);
        rb.push(6);
        rb.push(7); // This should overwrite oldest
        
        assert_eq!(rb.capacity(), 4);
    }

    #[test]
    fn test_concurrent_queue() {
        let queue = Arc::new(LockFreeQueue::new(1000));
        
        let queue_clone = queue.clone();
        let producer = thread::spawn(move || {
            for i in 0..100 {
                while queue_clone.push(i).is_err() {
                    thread::yield_now();
                }
            }
        });
        
        let queue_clone = queue.clone();
        let consumer = thread::spawn(move || {
            let mut count = 0;
            while count < 100 {
                if queue_clone.pop().is_some() {
                    count += 1;
                }
            }
            count
        });
        
        producer.join().unwrap();
        assert_eq!(consumer.join().unwrap(), 100);
    }

    #[test]
    fn test_spsc_queue() {
        let mut queue = SpscQueue::new(8);
        
        // Producer side
        queue.push(1).unwrap();
        queue.push(2).unwrap();
        queue.push(3).unwrap();
        
        // Consumer side
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        
        // Push more
        queue.push(4).unwrap();
        
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.pop(), Some(3));
        assert_eq!(queue.pop(), Some(4));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn test_lock_free_stack() {
        let stack = LockFreeStack::new();
        
        stack.push(1);
        stack.push(2);
        stack.push(3);
        
        // LIFO order
        assert_eq!(stack.pop(), Some(3));
        assert_eq!(stack.pop(), Some(2));
        assert_eq!(stack.pop(), Some(1));
        assert_eq!(stack.pop(), None);
        
        assert!(stack.is_empty());
    }

    #[test]
    fn test_concurrent_stack() {
        let stack = Arc::new(LockFreeStack::new());
        
        let stack_clone = stack.clone();
        let producer = thread::spawn(move || {
            for i in 0..100 {
                stack_clone.push(i);
            }
        });
        
        producer.join().unwrap();
        
        // Pop all items
        let mut count = 0;
        while stack.pop().is_some() {
            count += 1;
        }
        assert_eq!(count, 100);
    }

    #[test]
    fn test_atomic_ops() {
        let atomic = AtomicU64::new(10);
        
        // CAS operations
        assert!(AtomicOps::cas_u64(&atomic, 10, 20).is_ok());
        assert!(AtomicOps::cas_u64(&atomic, 10, 30).is_err());
        
        // Load/Store
        AtomicOps::store_release(&atomic, 100);
        assert_eq!(AtomicOps::load_acquire(&atomic), 100);
        
        // Fetch operations
        assert_eq!(AtomicOps::fetch_add_relaxed(&atomic, 50), 100);
        assert_eq!(AtomicOps::fetch_sub_relaxed(&atomic, 25), 150);
        assert_eq!(atomic.load(Ordering::Relaxed), 125);
    }

    #[test]
    fn test_cache_alignment() {
        use std::mem::{align_of, size_of};
        
        // Verify cache-line alignment
        assert_eq!(align_of::<CacheAligned<AtomicU64>>(), 64);
        assert!(size_of::<CacheAligned<AtomicU64>>() >= 64);
    }

    #[test]
    fn test_spsc_wait_free() {
        let mut queue = SpscQueue::new(1024);
        
        // Fill queue
        for i in 0..1000 {
            queue.push(i).unwrap();
        }
        
        // Drain queue
        for i in 0..1000 {
            assert_eq!(queue.pop(), Some(i));
        }
        
        assert!(queue.is_empty());
    }
}
