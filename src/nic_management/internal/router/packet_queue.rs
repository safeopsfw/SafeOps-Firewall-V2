//! High-Performance Lock-Free Packet Queues
//!
//! This module implements lock-free packet queues using ring buffers for
//! zero-copy packet buffering between capture, processing, and transmission stages.

use std::alloc::{alloc, dealloc, Layout};
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::ptr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use crossbeam::utils::CachePadded;

// =============================================================================
// Queue Type Enumeration
// =============================================================================

/// Queue type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueType {
    /// Single-producer single-consumer (fastest).
    SPSC,
    /// Multi-producer multi-consumer (most flexible).
    MPMC,
    /// Priority queue with multiple levels.
    Priority,
}

// =============================================================================
// Priority Level
// =============================================================================

/// Priority level enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// Real-time traffic (VoIP, video).
    High = 0,
    /// Interactive traffic (SSH, gaming).
    Medium = 1,
    /// Bulk traffic (file transfers).
    Low = 2,
    /// Background traffic.
    BestEffort = 3,
}

impl Default for Priority {
    fn default() -> Self {
        Priority::BestEffort
    }
}

// =============================================================================
// Queue Configuration
// =============================================================================

/// Queue configuration.
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// Queue capacity (must be power of 2).
    pub capacity: usize,
    /// Queue type.
    pub queue_type: QueueType,
    /// Block on full vs drop packets.
    pub enable_backpressure: bool,
    /// Collect queue statistics.
    pub enable_stats: bool,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            capacity: 4096,
            queue_type: QueueType::MPMC,
            enable_backpressure: false,
            enable_stats: true,
        }
    }
}

// =============================================================================
// Queue Statistics
// =============================================================================

/// Queue performance statistics.
#[derive(Debug, Clone, Default)]
pub struct QueueStats {
    /// Queue capacity.
    pub capacity: usize,
    /// Current packets in queue.
    pub current_size: usize,
    /// Total packets enqueued.
    pub enqueue_count: u64,
    /// Total packets dequeued.
    pub dequeue_count: u64,
    /// Packets dropped (queue full).
    pub drop_count: u64,
    /// Queue utilization (0-100%).
    pub utilization_percent: f32,
    /// Throughput in packets per second.
    pub throughput_pps: u64,
}

// =============================================================================
// Packet Buffer (Simplified for queue usage)
// =============================================================================

/// A packet buffer for queue storage.
#[derive(Debug)]
pub struct QueuePacket {
    /// Raw packet data.
    pub data: Vec<u8>,
    /// Packet length.
    pub len: usize,
    /// Source interface index.
    pub src_interface: u32,
    /// Destination interface index.
    pub dst_interface: u32,
    /// Timestamp.
    pub timestamp: u64,
    /// Priority.
    pub priority: Priority,
}

impl Default for QueuePacket {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            len: 0,
            src_interface: 0,
            dst_interface: 0,
            timestamp: 0,
            priority: Priority::BestEffort,
        }
    }
}

impl Clone for QueuePacket {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            len: self.len,
            src_interface: self.src_interface,
            dst_interface: self.dst_interface,
            timestamp: self.timestamp,
            priority: self.priority,
        }
    }
}

// =============================================================================
// Capacity Validation
// =============================================================================

/// Validates that capacity is a power of 2.
fn validate_capacity(capacity: usize) -> Result<(), &'static str> {
    if capacity == 0 {
        return Err("Capacity must be greater than 0");
    }
    if capacity & (capacity - 1) != 0 {
        return Err("Capacity must be a power of 2");
    }
    Ok(())
}

/// Rounds up to the next power of 2.
fn next_power_of_two(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    let mut v = n - 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    v + 1
}

// =============================================================================
// SPSC Queue - Single Producer Single Consumer
// =============================================================================

/// Lock-free single-producer single-consumer queue.
pub struct SPSCQueue<T> {
    /// Ring buffer storage.
    buffer: *mut UnsafeCell<MaybeUninit<T>>,
    /// Queue capacity (power of 2).
    capacity: usize,
    /// Capacity - 1 for fast modulo.
    mask: usize,
    /// Read position (consumer).
    head: CachePadded<AtomicUsize>,
    /// Write position (producer).
    tail: CachePadded<AtomicUsize>,
    /// Total enqueues.
    enqueue_count: AtomicU64,
    /// Total dequeues.
    dequeue_count: AtomicU64,
    /// Packets dropped.
    drop_count: AtomicU64,
}

impl<T> SPSCQueue<T> {
    /// Creates a new SPSC queue with the given capacity.
    pub fn new(capacity: usize) -> Self {
        let capacity = next_power_of_two(capacity);
        validate_capacity(capacity).expect("Invalid capacity");

        let layout = Layout::array::<UnsafeCell<MaybeUninit<T>>>(capacity).unwrap();
        let buffer = unsafe { alloc(layout) as *mut UnsafeCell<MaybeUninit<T>> };

        if buffer.is_null() {
            panic!("Failed to allocate queue buffer");
        }

        // Initialize all slots.
        for i in 0..capacity {
            unsafe {
                ptr::write(buffer.add(i), UnsafeCell::new(MaybeUninit::uninit()));
            }
        }

        Self {
            buffer,
            capacity,
            mask: capacity - 1,
            head: CachePadded::new(AtomicUsize::new(0)),
            tail: CachePadded::new(AtomicUsize::new(0)),
            enqueue_count: AtomicU64::new(0),
            dequeue_count: AtomicU64::new(0),
            drop_count: AtomicU64::new(0),
        }
    }

    /// Enqueues a value. Returns true on success, false if queue is full.
    pub fn enqueue(&self, value: T) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let next_tail = (tail + 1) & self.mask;

        // Check if full.
        if next_tail == self.head.load(Ordering::Acquire) {
            self.drop_count.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Write value.
        unsafe {
            let slot = &*self.buffer.add(tail);
            (*slot.get()).write(value);
        }

        // Publish write.
        self.tail.store(next_tail, Ordering::Release);
        self.enqueue_count.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Dequeues a value. Returns None if queue is empty.
    pub fn dequeue(&self) -> Option<T> {
        let head = self.head.load(Ordering::Relaxed);

        // Check if empty.
        if head == self.tail.load(Ordering::Acquire) {
            return None;
        }

        // Read value.
        let value = unsafe {
            let slot = &*self.buffer.add(head);
            (*slot.get()).assume_init_read()
        };

        // Publish read.
        let next_head = (head + 1) & self.mask;
        self.head.store(next_head, Ordering::Release);
        self.dequeue_count.fetch_add(1, Ordering::Relaxed);

        Some(value)
    }

    /// Returns the current number of items in the queue.
    pub fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Relaxed);
        (tail.wrapping_sub(head)) & self.mask
    }

    /// Returns true if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Relaxed) == self.tail.load(Ordering::Relaxed)
    }

    /// Returns queue statistics.
    pub fn get_stats(&self) -> QueueStats {
        let enqueue_count = self.enqueue_count.load(Ordering::Relaxed);
        let dequeue_count = self.dequeue_count.load(Ordering::Relaxed);
        let current_size = self.len();
        let utilization = (current_size as f32 / self.capacity as f32) * 100.0;

        QueueStats {
            capacity: self.capacity,
            current_size,
            enqueue_count,
            dequeue_count,
            drop_count: self.drop_count.load(Ordering::Relaxed),
            utilization_percent: utilization,
            throughput_pps: 0, // Would need timing to calculate.
        }
    }
}

impl<T> Drop for SPSCQueue<T> {
    fn drop(&mut self) {
        // Drain remaining items.
        while self.dequeue().is_some() {}

        // Deallocate buffer.
        let layout = Layout::array::<UnsafeCell<MaybeUninit<T>>>(self.capacity).unwrap();
        unsafe {
            dealloc(self.buffer as *mut u8, layout);
        }
    }
}

// SPSC is safe to send between threads.
unsafe impl<T: Send> Send for SPSCQueue<T> {}
// SPSC is sync only with proper producer/consumer discipline.
unsafe impl<T: Send> Sync for SPSCQueue<T> {}

// =============================================================================
// MPMC Queue Slot
// =============================================================================

/// A slot in the MPMC queue with sequence number.
struct Slot<T> {
    /// Sequence number for synchronization.
    sequence: AtomicUsize,
    /// The data.
    data: UnsafeCell<MaybeUninit<T>>,
}

// =============================================================================
// MPMC Queue - Multi Producer Multi Consumer
// =============================================================================

/// Lock-free multi-producer multi-consumer queue.
pub struct MPMCQueue<T> {
    /// Ring buffer with slots.
    buffer: *mut Slot<T>,
    /// Queue capacity.
    capacity: usize,
    /// Capacity - 1 for fast modulo.
    mask: usize,
    /// Read position.
    head: CachePadded<AtomicUsize>,
    /// Write position.
    tail: CachePadded<AtomicUsize>,
    /// Total enqueues.
    enqueue_count: AtomicU64,
    /// Total dequeues.
    dequeue_count: AtomicU64,
    /// Packets dropped.
    drop_count: AtomicU64,
}

impl<T> MPMCQueue<T> {
    /// Creates a new MPMC queue with the given capacity.
    pub fn new(capacity: usize) -> Self {
        let capacity = next_power_of_two(capacity);
        validate_capacity(capacity).expect("Invalid capacity");

        let layout = Layout::array::<Slot<T>>(capacity).unwrap();
        let buffer = unsafe { alloc(layout) as *mut Slot<T> };

        if buffer.is_null() {
            panic!("Failed to allocate queue buffer");
        }

        // Initialize all slots with sequence numbers.
        for i in 0..capacity {
            unsafe {
                ptr::write(
                    buffer.add(i),
                    Slot {
                        sequence: AtomicUsize::new(i),
                        data: UnsafeCell::new(MaybeUninit::uninit()),
                    },
                );
            }
        }

        Self {
            buffer,
            capacity,
            mask: capacity - 1,
            head: CachePadded::new(AtomicUsize::new(0)),
            tail: CachePadded::new(AtomicUsize::new(0)),
            enqueue_count: AtomicU64::new(0),
            dequeue_count: AtomicU64::new(0),
            drop_count: AtomicU64::new(0),
        }
    }

    /// Enqueues a value. Returns true on success, false if queue is full.
    pub fn enqueue(&self, value: T) -> bool {
        let mut tail = self.tail.load(Ordering::Relaxed);

        loop {
            let slot = unsafe { &*self.buffer.add(tail & self.mask) };
            let seq = slot.sequence.load(Ordering::Acquire);
            let diff = seq as isize - tail as isize;

            if diff == 0 {
                // Slot is ready for writing.
                match self.tail.compare_exchange_weak(
                    tail,
                    tail.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // Write data.
                        unsafe {
                            (*slot.data.get()).write(value);
                        }
                        // Publish.
                        slot.sequence.store(tail.wrapping_add(1), Ordering::Release);
                        self.enqueue_count.fetch_add(1, Ordering::Relaxed);
                        return true;
                    }
                    Err(t) => {
                        tail = t;
                    }
                }
            } else if diff < 0 {
                // Queue is full.
                self.drop_count.fetch_add(1, Ordering::Relaxed);
                return false;
            } else {
                // Another producer is ahead, reload tail.
                tail = self.tail.load(Ordering::Relaxed);
            }
        }
    }

    /// Dequeues a value. Returns None if queue is empty.
    pub fn dequeue(&self) -> Option<T> {
        let mut head = self.head.load(Ordering::Relaxed);

        loop {
            let slot = unsafe { &*self.buffer.add(head & self.mask) };
            let seq = slot.sequence.load(Ordering::Acquire);
            let diff = seq as isize - (head.wrapping_add(1)) as isize;

            if diff == 0 {
                // Slot has data.
                match self.head.compare_exchange_weak(
                    head,
                    head.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // Read data.
                        let value = unsafe { (*slot.data.get()).assume_init_read() };
                        // Publish.
                        slot.sequence
                            .store(head.wrapping_add(self.capacity), Ordering::Release);
                        self.dequeue_count.fetch_add(1, Ordering::Relaxed);
                        return Some(value);
                    }
                    Err(h) => {
                        head = h;
                    }
                }
            } else if diff < 0 {
                // Queue is empty.
                return None;
            } else {
                // Another consumer is ahead, reload head.
                head = self.head.load(Ordering::Relaxed);
            }
        }
    }

    /// Returns the approximate number of items in the queue.
    pub fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Relaxed);
        tail.wrapping_sub(head)
    }

    /// Returns true if the queue appears empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns queue statistics.
    pub fn get_stats(&self) -> QueueStats {
        let enqueue_count = self.enqueue_count.load(Ordering::Relaxed);
        let dequeue_count = self.dequeue_count.load(Ordering::Relaxed);
        let current_size = self.len();
        let utilization = (current_size as f32 / self.capacity as f32) * 100.0;

        QueueStats {
            capacity: self.capacity,
            current_size,
            enqueue_count,
            dequeue_count,
            drop_count: self.drop_count.load(Ordering::Relaxed),
            utilization_percent: utilization.min(100.0),
            throughput_pps: 0,
        }
    }
}

impl<T> Drop for MPMCQueue<T> {
    fn drop(&mut self) {
        // Drain remaining items.
        while self.dequeue().is_some() {}

        // Drop slots.
        for i in 0..self.capacity {
            unsafe {
                ptr::drop_in_place(self.buffer.add(i));
            }
        }

        // Deallocate buffer.
        let layout = Layout::array::<Slot<T>>(self.capacity).unwrap();
        unsafe {
            dealloc(self.buffer as *mut u8, layout);
        }
    }
}

unsafe impl<T: Send> Send for MPMCQueue<T> {}
unsafe impl<T: Send> Sync for MPMCQueue<T> {}

// =============================================================================
// Priority Queue
// =============================================================================

/// Multi-level priority queue for QoS.
pub struct PriorityQueue<T: Send> {
    /// High priority queue (real-time traffic).
    high_priority: Arc<MPMCQueue<T>>,
    /// Medium priority queue (interactive).
    medium_priority: Arc<MPMCQueue<T>>,
    /// Low priority queue (bulk).
    low_priority: Arc<MPMCQueue<T>>,
    /// Best effort queue (background).
    best_effort: Arc<MPMCQueue<T>>,
    /// Total enqueues.
    total_enqueues: AtomicU64,
    /// Total dequeues.
    total_dequeues: AtomicU64,
}

impl<T: Send> PriorityQueue<T> {
    /// Creates a new priority queue with the given capacity per level.
    pub fn new(capacity_per_level: usize) -> Self {
        Self {
            high_priority: Arc::new(MPMCQueue::new(capacity_per_level)),
            medium_priority: Arc::new(MPMCQueue::new(capacity_per_level)),
            low_priority: Arc::new(MPMCQueue::new(capacity_per_level)),
            best_effort: Arc::new(MPMCQueue::new(capacity_per_level)),
            total_enqueues: AtomicU64::new(0),
            total_dequeues: AtomicU64::new(0),
        }
    }

    /// Enqueues a value with the given priority.
    pub fn enqueue(&self, value: T, priority: Priority) -> bool {
        let result = match priority {
            Priority::High => self.high_priority.enqueue(value),
            Priority::Medium => self.medium_priority.enqueue(value),
            Priority::Low => self.low_priority.enqueue(value),
            Priority::BestEffort => self.best_effort.enqueue(value),
        };

        if result {
            self.total_enqueues.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Dequeues the highest priority value available.
    pub fn dequeue(&self) -> Option<T> {
        // Strict priority scheduling.
        if let Some(v) = self.high_priority.dequeue() {
            self.total_dequeues.fetch_add(1, Ordering::Relaxed);
            return Some(v);
        }
        if let Some(v) = self.medium_priority.dequeue() {
            self.total_dequeues.fetch_add(1, Ordering::Relaxed);
            return Some(v);
        }
        if let Some(v) = self.low_priority.dequeue() {
            self.total_dequeues.fetch_add(1, Ordering::Relaxed);
            return Some(v);
        }
        if let Some(v) = self.best_effort.dequeue() {
            self.total_dequeues.fetch_add(1, Ordering::Relaxed);
            return Some(v);
        }
        None
    }

    /// Returns the total number of items across all queues.
    pub fn len(&self) -> usize {
        self.high_priority.len()
            + self.medium_priority.len()
            + self.low_priority.len()
            + self.best_effort.len()
    }

    /// Returns true if all queues are empty.
    pub fn is_empty(&self) -> bool {
        self.high_priority.is_empty()
            && self.medium_priority.is_empty()
            && self.low_priority.is_empty()
            && self.best_effort.is_empty()
    }

    /// Returns statistics for a specific priority level.
    pub fn get_priority_stats(&self, priority: Priority) -> QueueStats {
        match priority {
            Priority::High => self.high_priority.get_stats(),
            Priority::Medium => self.medium_priority.get_stats(),
            Priority::Low => self.low_priority.get_stats(),
            Priority::BestEffort => self.best_effort.get_stats(),
        }
    }

    /// Returns aggregate statistics.
    pub fn get_stats(&self) -> QueueStats {
        QueueStats {
            capacity: self.high_priority.capacity * 4,
            current_size: self.len(),
            enqueue_count: self.total_enqueues.load(Ordering::Relaxed),
            dequeue_count: self.total_dequeues.load(Ordering::Relaxed),
            drop_count: self.high_priority.drop_count.load(Ordering::Relaxed)
                + self.medium_priority.drop_count.load(Ordering::Relaxed)
                + self.low_priority.drop_count.load(Ordering::Relaxed)
                + self.best_effort.drop_count.load(Ordering::Relaxed),
            utilization_percent: 0.0,
            throughput_pps: 0,
        }
    }
}

unsafe impl<T: Send> Send for PriorityQueue<T> {}
unsafe impl<T: Send> Sync for PriorityQueue<T> {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_capacity_validation() {
        assert!(validate_capacity(0).is_err());
        assert!(validate_capacity(3).is_err());
        assert!(validate_capacity(1).is_ok());
        assert!(validate_capacity(2).is_ok());
        assert!(validate_capacity(4).is_ok());
        assert!(validate_capacity(1024).is_ok());
    }

    #[test]
    fn test_next_power_of_two() {
        assert_eq!(next_power_of_two(0), 1);
        assert_eq!(next_power_of_two(1), 1);
        assert_eq!(next_power_of_two(2), 2);
        assert_eq!(next_power_of_two(3), 4);
        assert_eq!(next_power_of_two(5), 8);
        assert_eq!(next_power_of_two(1000), 1024);
    }

    #[test]
    fn test_spsc_basic() {
        let queue: SPSCQueue<i32> = SPSCQueue::new(4);

        assert!(queue.is_empty());
        assert!(queue.enqueue(1));
        assert!(queue.enqueue(2));
        assert!(!queue.is_empty());

        assert_eq!(queue.dequeue(), Some(1));
        assert_eq!(queue.dequeue(), Some(2));
        assert_eq!(queue.dequeue(), None);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_spsc_full() {
        let queue: SPSCQueue<i32> = SPSCQueue::new(4);

        // Fill queue (capacity is 4, but usable is 3 due to ring buffer).
        assert!(queue.enqueue(1));
        assert!(queue.enqueue(2));
        assert!(queue.enqueue(3));
        assert!(!queue.enqueue(4)); // Should fail, queue full.

        let stats = queue.get_stats();
        assert_eq!(stats.drop_count, 1);
    }

    #[test]
    fn test_mpmc_basic() {
        let queue: MPMCQueue<i32> = MPMCQueue::new(8);

        assert!(queue.is_empty());
        assert!(queue.enqueue(1));
        assert!(queue.enqueue(2));
        assert!(queue.enqueue(3));

        assert_eq!(queue.dequeue(), Some(1));
        assert_eq!(queue.dequeue(), Some(2));
        assert_eq!(queue.dequeue(), Some(3));
        assert_eq!(queue.dequeue(), None);
    }

    #[test]
    fn test_mpmc_concurrent() {
        let queue = Arc::new(MPMCQueue::new(1024));
        let mut handles = vec![];

        // Spawn producers.
        for _ in 0..4 {
            let q = Arc::clone(&queue);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    while !q.enqueue(i) {
                        thread::yield_now();
                    }
                }
            }));
        }

        // Spawn consumers.
        let consumed = Arc::new(AtomicUsize::new(0));
        for _ in 0..4 {
            let q = Arc::clone(&queue);
            let c = Arc::clone(&consumed);
            handles.push(thread::spawn(move || loop {
                if c.load(Ordering::Relaxed) >= 400 {
                    break;
                }
                if q.dequeue().is_some() {
                    c.fetch_add(1, Ordering::Relaxed);
                } else {
                    thread::yield_now();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(consumed.load(Ordering::Relaxed), 400);
    }

    #[test]
    fn test_priority_ordering() {
        let queue: PriorityQueue<i32> = PriorityQueue::new(16);

        // Enqueue in reverse priority order.
        assert!(queue.enqueue(4, Priority::BestEffort));
        assert!(queue.enqueue(3, Priority::Low));
        assert!(queue.enqueue(2, Priority::Medium));
        assert!(queue.enqueue(1, Priority::High));

        // Should dequeue in priority order.
        assert_eq!(queue.dequeue(), Some(1)); // High
        assert_eq!(queue.dequeue(), Some(2)); // Medium
        assert_eq!(queue.dequeue(), Some(3)); // Low
        assert_eq!(queue.dequeue(), Some(4)); // BestEffort
        assert_eq!(queue.dequeue(), None);
    }

    #[test]
    fn test_queue_stats() {
        let queue: SPSCQueue<i32> = SPSCQueue::new(8);

        queue.enqueue(1);
        queue.enqueue(2);
        queue.dequeue();

        let stats = queue.get_stats();
        assert_eq!(stats.capacity, 8);
        assert_eq!(stats.enqueue_count, 2);
        assert_eq!(stats.dequeue_count, 1);
        assert_eq!(stats.current_size, 1);
    }

    #[test]
    fn test_queue_packet() {
        let queue: SPSCQueue<QueuePacket> = SPSCQueue::new(4);

        let packet = QueuePacket {
            data: vec![1, 2, 3, 4],
            len: 4,
            src_interface: 1,
            dst_interface: 2,
            timestamp: 12345,
            priority: Priority::High,
        };

        assert!(queue.enqueue(packet));
        let dequeued = queue.dequeue().unwrap();
        assert_eq!(dequeued.data, vec![1, 2, 3, 4]);
        assert_eq!(dequeued.src_interface, 1);
        assert_eq!(dequeued.priority, Priority::High);
    }
}
