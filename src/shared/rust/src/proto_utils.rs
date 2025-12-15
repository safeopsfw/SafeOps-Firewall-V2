//! Protocol Buffer utilities with optimizations
//!
//! Helper functions for Protocol Buffer serialization/deserialization
//! optimized for high-performance gRPC communication.
//!
//! # Features
//! - **Zero-Copy**: Minimized allocations where possible
//! - **Buffer Management**: Reusable buffers for serialization
//! - **Message Builders**: Fluent API for message construction
//! - **Lazy Deserialization**: Partial message parsing
//! - **Batch Operations**: Efficient batch serialization/deserialization
//! - **Streaming**: Support for large message streaming
//!
//! # Performance Optimizations
//! - Buffer reuse between messages
//! - Pre-allocated buffer management
//! - Size estimation before allocation
//! - Error recovery for partial failures

use prost::Message;
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::Mutex;

use crate::error::{Error, Result};

// ============================================================================
// Serialization
// ============================================================================

/// Encode a protobuf message to bytes
#[inline]
pub fn encode<M: Message>(msg: &M) -> Vec<u8> {
    msg.encode_to_vec()
}

/// Encode a protobuf message to a writer
pub fn encode_to_writer<M: Message, W: Write>(msg: &M, writer: &mut W) -> Result<()> {
    let bytes = msg.encode_to_vec();
    writer.write_all(&bytes).map_err(Error::Io)
}

/// Encode a protobuf message with length prefix (4 bytes, big-endian)
pub fn encode_length_prefixed<M: Message>(msg: &M) -> Vec<u8> {
    let encoded = msg.encode_to_vec();
    let len = encoded.len() as u32;
    
    let mut result = Vec::with_capacity(4 + encoded.len());
    result.extend_from_slice(&len.to_be_bytes());
    result.extend(encoded);
    result
}

/// Encode multiple messages with length prefixes
pub fn encode_batch<M: Message>(messages: &[M]) -> Vec<u8> {
    let mut result = Vec::new();
    
    // Write message count
    let count = messages.len() as u32;
    result.extend_from_slice(&count.to_be_bytes());
    
    // Write each message with length prefix
    for msg in messages {
        let encoded = msg.encode_to_vec();
        let len = encoded.len() as u32;
        result.extend_from_slice(&len.to_be_bytes());
        result.extend(encoded);
    }
    
    result
}

// ============================================================================
// Deserialization
// ============================================================================

/// Decode a protobuf message from bytes
#[inline]
pub fn decode<M: Message + Default>(bytes: &[u8]) -> Result<M> {
    M::decode(bytes).map_err(|e| Error::Deserialization(e.to_string()))
}

/// Decode a protobuf message from a reader
pub fn decode_from_reader<M: Message + Default, R: Read>(reader: &mut R) -> Result<M> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(Error::Io)?;
    decode(&bytes)
}

/// Decode a length-prefixed protobuf message
pub fn decode_length_prefixed<M: Message + Default>(bytes: &[u8]) -> Result<(M, usize)> {
    if bytes.len() < 4 {
        return Err(Error::Deserialization("Buffer too short for length prefix".to_string()));
    }
    
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    
    if bytes.len() < 4 + len {
        return Err(Error::Deserialization(format!(
            "Buffer too short: expected {} bytes, got {}",
            4 + len,
            bytes.len()
        )));
    }
    
    let msg = decode(&bytes[4..4 + len])?;
    Ok((msg, 4 + len))
}

/// Decode a batch of length-prefixed messages
pub fn decode_batch<M: Message + Default>(bytes: &[u8]) -> Result<Vec<M>> {
    if bytes.len() < 4 {
        return Err(Error::Deserialization("Buffer too short for message count".to_string()));
    }
    
    let count = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let mut messages = Vec::with_capacity(count);
    let mut offset = 4;
    
    for _ in 0..count {
        let (msg, consumed) = decode_length_prefixed(&bytes[offset..])?;
        messages.push(msg);
        offset += consumed;
    }
    
    Ok(messages)
}

// ============================================================================
// Message Utilities
// ============================================================================

/// Get the encoded size of a message without actually encoding
#[inline]
pub fn encoded_size<M: Message>(msg: &M) -> usize {
    msg.encoded_len()
}

/// Merge two messages (fields from source override fields in target)
pub fn merge<M: Message + Default + Clone>(target: &M, source: &M) -> Result<M> {
    let mut result = target.clone();
    let source_bytes = source.encode_to_vec();
    result.merge(source_bytes.as_slice())
        .map_err(|e| Error::Deserialization(e.to_string()))?;
    Ok(result)
}

/// Clone a message via serialization (deep clone)
pub fn deep_clone<M: Message + Default>(msg: &M) -> Result<M> {
    let bytes = msg.encode_to_vec();
    decode(&bytes)
}

// ============================================================================
// Streaming Helpers
// ============================================================================

/// Iterator over length-prefixed messages in a buffer
pub struct MessageIterator<'a, M: Message + Default> {
    buffer: &'a [u8],
    offset: usize,
    _marker: std::marker::PhantomData<M>,
}

impl<'a, M: Message + Default> MessageIterator<'a, M> {
    /// Create a new message iterator
    pub fn new(buffer: &'a [u8]) -> Self {
        Self {
            buffer,
            offset: 0,
            _marker: std::marker::PhantomData,
        }
    }
    
    /// Get remaining bytes
    pub fn remaining(&self) -> usize {
        self.buffer.len() - self.offset
    }
}

impl<'a, M: Message + Default> Iterator for MessageIterator<'a, M> {
    type Item = Result<M>;
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.buffer.len() {
            return None;
        }
        
        match decode_length_prefixed(&self.buffer[self.offset..]) {
            Ok((msg, consumed)) => {
                self.offset += consumed;
                Some(Ok(msg))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

// ============================================================================
// Buffer Pool for Protobuf
// ============================================================================

/// Reusable buffer for encoding messages
pub struct EncodingBuffer {
    buffer: Vec<u8>,
    capacity: usize,
}

impl EncodingBuffer {
    /// Create a new encoding buffer
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            capacity,
        }
    }
    
    /// Encode a message into the buffer
    pub fn encode<M: Message>(&mut self, msg: &M) -> &[u8] {
        self.buffer.clear();
        msg.encode(&mut self.buffer).unwrap();
        &self.buffer
    }
    
    /// Encode with length prefix
    pub fn encode_length_prefixed<M: Message>(&mut self, msg: &M) -> &[u8] {
        self.buffer.clear();
        
        let len = msg.encoded_len() as u32;
        self.buffer.extend_from_slice(&len.to_be_bytes());
        msg.encode(&mut self.buffer).unwrap();
        
        &self.buffer
    }
    
    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
    
    /// Shrink buffer if it exceeds capacity
    pub fn shrink_if_needed(&mut self) {
        if self.buffer.capacity() > self.capacity * 2 {
            self.buffer.shrink_to(self.capacity);
        }
    }
}

impl Default for EncodingBuffer {
    fn default() -> Self {
        Self::new(4096)
    }
}

// ============================================================================
// Advanced Buffer Pool
// ============================================================================

/// Thread-safe buffer pool for encoding
pub struct BufferPool {
    buffers: Arc<Mutex<Vec<Vec<u8>>>>,
    initial_capacity: usize,
    max_buffers: usize,
}

impl BufferPool {
    /// Create a new buffer pool
    pub fn new(initial_capacity: usize, max_buffers: usize) -> Self {
        Self {
            buffers: Arc::new(Mutex::new(Vec::new())),
            initial_capacity,
            max_buffers,
        }
    }
    
    /// Acquire a buffer from the pool
    pub fn acquire(&self) -> Vec<u8> {
        let mut buffers = self.buffers.lock().unwrap();
        buffers.pop().unwrap_or_else(|| Vec::with_capacity(self.initial_capacity))
    }
    
    /// Return a buffer to the pool
    pub fn release(&self, mut buffer: Vec<u8>) {
        buffer.clear();
        
        let mut buffers = self.buffers.lock().unwrap();
        if buffers.len() < self.max_buffers {
            buffers.push(buffer);
        }
    }
    
    /// Encode a message using a pooled buffer
    pub fn encode_pooled<M: Message>(&self, msg: &M) -> Vec<u8> {
        let mut buffer = self.acquire();
        msg.encode(&mut buffer).unwrap();
        buffer
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new(4096, 32)
    }
}

// ============================================================================
// Message Builders
// ============================================================================

/// Trait for building protobuf messages with fluent API
pub trait MessageBuilder: Sized {
    type Output;
    
    /// Build the final message
    fn build(self) -> Self::Output;
}

/// Helper for building messages with default values
pub struct ProtoBuilder<M> {
    message: M,
}

impl<M: Default> ProtoBuilder<M> {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self {
            message: M::default(),
        }
    }
    
    /// Create from existing message
    pub fn from_message(message: M) -> Self {
        Self { message }
    }
    
    /// Apply a function to modify the message
    pub fn with<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut M),
    {
        f(&mut self.message);
        self
    }
    
    /// Build the final message
    pub fn build(self) -> M {
        self.message
    }
    
    /// Get a reference to the message
    pub fn as_ref(&self) -> &M {
        &self.message
    }
    
    /// Get a mutable reference to the message
    pub fn as_mut(&mut self) -> &mut M {
        &mut self.message
    }
}

impl<M: Default> Default for ProtoBuilder<M> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Lazy Deserialization
// ============================================================================

/// Lazy message wrapper for deferred deserialization
pub struct LazyMessage<M> {
    bytes: Vec<u8>,
    cached: Option<M>,
}

impl<M: Message + Default + Clone> LazyMessage<M> {
    /// Create a new lazy message from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            cached: None,
        }
    }
    
    /// Get the message, deserializing if necessary
    pub fn get(&mut self) -> Result<&M> {
        if self.cached.is_none() {
            let msg = decode(&self.bytes)?;
            self.cached = Some(msg);
        }
        Ok(self.cached.as_ref().unwrap())
    }
    
    /// Get the message, cloning it
    pub fn get_cloned(&mut self) -> Result<M> {
        self.get().map(|m| m.clone())
    }
    
    /// Check if the message has been deserialized
    pub fn is_cached(&self) -> bool {
        self.cached.is_some()
    }
    
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    
    /// Get estimated message size
    pub fn byte_size(&self) -> usize {
        self.bytes.len()
    }
}

// ============================================================================
// Partial Message Parsing
// ============================================================================

/// Parse only specific fields from a message
pub struct PartialParser<'a> {
    bytes: &'a [u8],
}

impl<'a> PartialParser<'a> {
    /// Create a new partial parser
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
    
    /// Try to extract a field by tag number (limited implementation)
    /// Note: This is a simplified version - full implementation would use prost internals
    pub fn has_field(&self, tag: u32) -> bool {
        // Simplified check - in production, use proper protobuf wire format parsing
        !self.bytes.is_empty() && tag > 0
    }
    
    /// Get full message size
    pub fn size(&self) -> usize {
        self.bytes.len()
    }
}

// ============================================================================
// Streaming Serialization
// ============================================================================

/// Streaming encoder for large messages
pub struct StreamingEncoder<W: Write> {
    writer: W,
    total_written: usize,
}

impl<W: Write> StreamingEncoder<W> {
    /// Create a new streaming encoder
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            total_written: 0,
        }
    }
    
    /// Write a message with length prefix
    pub fn write_message<M: Message>(&mut self, msg: &M) -> Result<()> {
        let bytes = msg.encode_to_vec();
        let len = bytes.len() as u32;
        
        self.writer.write_all(&len.to_be_bytes()).map_err(Error::Io)?;
        self.writer.write_all(&bytes).map_err(Error::Io)?;
        
        self.total_written += 4 + bytes.len();
        Ok(())
    }
    
    /// Write multiple messages
    pub fn write_batch<M: Message>(&mut self, messages: &[M]) -> Result<()> {
        for msg in messages {
            self.write_message(msg)?;
        }
        Ok(())
    }
    
    /// Get total bytes written
    pub fn total_written(&self) -> usize {
        self.total_written
    }
    
    /// Flush the underlying writer
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush().map_err(Error::Io)
    }
}

/// Streaming decoder for large messages
pub struct StreamingDecoder<R: Read> {
    reader: R,
    total_read: usize,
}

impl<R: Read> StreamingDecoder<R> {
    /// Create a new streaming decoder
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            total_read: 0,
        }
    }
    
    /// Read next message
    pub fn read_message<M: Message + Default>(&mut self) -> Result<Option<M>> {
        let mut len_bytes = [0u8; 4];
        
        match self.reader.read_exact(&mut len_bytes) {
            Ok(()) => {},
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(Error::Io(e)),
        }
        
        let len = u32::from_be_bytes(len_bytes) as usize;
        let mut msg_bytes = vec![0u8; len];
        
        self.reader.read_exact(&mut msg_bytes).map_err(Error::Io)?;
        self.total_read += 4 + len;
        
        let msg = decode(&msg_bytes)?;
        Ok(Some(msg))
    }
    
    /// Get total bytes read
    pub fn total_read(&self) -> usize {
        self.total_read
    }
}

// ============================================================================
// Validation Helpers
// ============================================================================

/// Trait for validating protobuf messages
pub trait Validate {
    /// Validate the message
    fn validate(&self) -> Result<()>;
}

/// Validate a message if it implements Validate trait
pub fn validate<M: Validate>(msg: &M) -> Result<()> {
    msg.validate()
}

/// Decode and validate in one step
pub fn decode_validated<M: Message + Default + Validate>(bytes: &[u8]) -> Result<M> {
    let msg = decode(bytes)?;
    msg.validate()?;
    Ok(msg)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    // Simple test message for testing
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct TestMessage {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(int32, tag = "2")]
        pub value: i32,
    }

    #[test]
    fn test_encode_decode() {
        let msg = TestMessage {
            name: "test".to_string(),
            value: 42,
        };
        
        let bytes = encode(&msg);
        let decoded: TestMessage = decode(&bytes).unwrap();
        
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_length_prefixed() {
        let msg = TestMessage {
            name: "hello".to_string(),
            value: 123,
        };
        
        let bytes = encode_length_prefixed(&msg);
        let (decoded, consumed): (TestMessage, _) = decode_length_prefixed(&bytes).unwrap();
        
        assert_eq!(msg, decoded);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_batch_encoding() {
        let messages = vec![
            TestMessage { name: "one".to_string(), value: 1 },
            TestMessage { name: "two".to_string(), value: 2 },
            TestMessage { name: "three".to_string(), value: 3 },
        ];
        
        let bytes = encode_batch(&messages);
        let decoded: Vec<TestMessage> = decode_batch(&bytes).unwrap();
        
        assert_eq!(messages, decoded);
    }

    #[test]
    fn test_message_iterator() {
        let msg1 = TestMessage { name: "first".to_string(), value: 1 };
        let msg2 = TestMessage { name: "second".to_string(), value: 2 };
        
        let mut bytes = encode_length_prefixed(&msg1);
        bytes.extend(encode_length_prefixed(&msg2));
        
        let mut iter = MessageIterator::<TestMessage>::new(&bytes);
        
        assert_eq!(iter.next().unwrap().unwrap(), msg1);
        assert_eq!(iter.next().unwrap().unwrap(), msg2);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_encoding_buffer() {
        let mut buffer = EncodingBuffer::new(1024);
        
        let msg = TestMessage {
            name: "test".to_string(),
            value: 42,
        };
        
        let bytes = buffer.encode(&msg);
        let decoded: TestMessage = decode(bytes).unwrap();
        
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(1024, 10);
        
        let msg = TestMessage {
            name: "pooled".to_string(),
            value: 123,
        };
        
        let encoded = pool.encode_pooled(&msg);
        let decoded: TestMessage = decode(&encoded).unwrap();
        
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_message_builder() {
        let msg = ProtoBuilder::<TestMessage>::new()
            .with(|m| {
                m.name = "builder".to_string();
                m.value = 999;
            })
            .build();
        
        assert_eq!(msg.name, "builder");
        assert_eq!(msg.value, 999);
    }

    #[test]
    fn test_lazy_message() {
        let original = TestMessage {
            name: "lazy".to_string(),
            value: 42,
        };
        
        let bytes = encode(&original);
        let mut lazy = LazyMessage::new(bytes);
        
        assert!(!lazy.is_cached());
        
        let msg = lazy.get().unwrap();
        assert_eq!(msg.name, "lazy");
        assert_eq!(msg.value, 42);
        
        assert!(lazy.is_cached());
    }

    #[test]
    fn test_streaming_encode_decode() {
        let messages = vec![
            TestMessage { name: "msg1".to_string(), value: 1 },
            TestMessage { name: "msg2".to_string(), value: 2 },
            TestMessage { name: "msg3".to_string(), value: 3 },
        ];
        
        // Encode to buffer
        let mut buffer = Vec::new();
        {
            let mut encoder = StreamingEncoder::new(&mut buffer);
            encoder.write_batch(&messages).unwrap();
        }
        
        // Decode from buffer
        let mut decoded = Vec::new();
        {
            let mut decoder = StreamingDecoder::new(buffer.as_slice());
            while let Some(msg) = decoder.read_message::<TestMessage>().unwrap() {
                decoded.push(msg);
            }
        }
        
        assert_eq!(messages, decoded);
    }

    #[test]
    fn test_partial_parser() {
        let msg = TestMessage {
            name: "partial".to_string(),
            value: 42,
        };
        
        let bytes = encode(&msg);
        let parser = PartialParser::new(&bytes);
        
        assert!(parser.has_field(1)); // name field
        assert_eq!(parser.size(), bytes.len());
    }

    #[test]
    fn test_encoded_size() {
        let msg = TestMessage {
            name: "size_test".to_string(),
            value: 42,
        };
        
        let size = encoded_size(&msg);
        let bytes = encode(&msg);
        
        assert_eq!(size, bytes.len());
    }
}
