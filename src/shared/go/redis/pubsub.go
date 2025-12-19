// Package redis provides pub/sub functionality.
package redis

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/go-redis/redis/v8"
)

// PubSub wraps Redis pub/sub functionality
type PubSub struct {
	client   *Client
	pubsub   *redis.PubSub
	handlers map[string]MessageHandler
	mu       sync.RWMutex
}

// MessageHandler handles received messages
type MessageHandler func(channel string, payload string)

// NewPubSub creates a new pub/sub instance
func NewPubSub(client *Client) *PubSub {
	return &PubSub{
		client:   client,
		handlers: make(map[string]MessageHandler),
	}
}

// Subscribe subscribes to channels
func (ps *PubSub) Subscribe(ctx context.Context, channels ...string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if ps.pubsub == nil {
		ps.pubsub = ps.client.Client.Subscribe(ctx, channels...)
	} else {
		ps.pubsub.Subscribe(ctx, channels...)
	}

	return nil
}

// Unsubscribe unsubscribes from channels
func (ps *PubSub) Unsubscribe(ctx context.Context, channels ...string) error {
	if ps.pubsub == nil {
		return nil
	}
	return ps.pubsub.Unsubscribe(ctx, channels...)
}

// PSubscribe subscribes to patterns
func (ps *PubSub) PSubscribe(ctx context.Context, patterns ...string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if ps.pubsub == nil {
		ps.pubsub = ps.client.Client.PSubscribe(ctx, patterns...)
	} else {
		ps.pubsub.PSubscribe(ctx, patterns...)
	}

	return nil
}

// RegisterHandler registers a handler for a channel
func (ps *PubSub) RegisterHandler(channel string, handler MessageHandler) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.handlers[channel] = handler
}

// Start starts receiving messages
func (ps *PubSub) Start(ctx context.Context) {
	if ps.pubsub == nil {
		return
	}

	ch := ps.pubsub.Channel()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-ch:
				if msg == nil {
					continue
				}

				ps.mu.RLock()
				if handler, ok := ps.handlers[msg.Channel]; ok {
					go handler(msg.Channel, msg.Payload)
				}
				// Also check for pattern handlers
				for pattern, handler := range ps.handlers {
					if matchPattern(pattern, msg.Channel) {
						go handler(msg.Channel, msg.Payload)
					}
				}
				ps.mu.RUnlock()
			}
		}
	}()
}

// Publish publishes a message
func (ps *PubSub) Publish(ctx context.Context, channel, message string) error {
	return ps.client.Client.Publish(ctx, channel, message).Err()
}

// Close closes the pub/sub connection
func (ps *PubSub) Close() error {
	if ps.pubsub == nil {
		return nil
	}
	return ps.pubsub.Close()
}

// matchPattern checks if a channel matches a pattern
func matchPattern(pattern, channel string) bool {
	// Simple pattern matching - in production use a proper glob matcher
	if pattern == channel {
		return true
	}
	// Handle * wildcard at end
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(channel) >= len(prefix) && channel[:len(prefix)] == prefix
	}
	return false
}

// Subscriber provides a simpler subscription interface
type Subscriber struct {
	pubsub  *PubSub
	channel string
	ch      chan string
}

// NewSubscriber creates a subscriber for a single channel
func (c *Client) NewSubscriber(ctx context.Context, channel string, bufferSize int) (*Subscriber, error) {
	ps := NewPubSub(c)

	if err := ps.Subscribe(ctx, channel); err != nil {
		return nil, err
	}

	sub := &Subscriber{
		pubsub:  ps,
		channel: channel,
		ch:      make(chan string, bufferSize),
	}

	ps.RegisterHandler(channel, func(ch, payload string) {
		select {
		case sub.ch <- payload:
		default:
			// Buffer full, drop message
		}
	})

	ps.Start(ctx)

	return sub, nil
}

// Receive returns the channel for receiving messages
func (s *Subscriber) Receive() <-chan string {
	return s.ch
}

// Close closes the subscriber
func (s *Subscriber) Close() error {
	close(s.ch)
	return s.pubsub.Close()
}

// Publisher provides a simple publish interface
type Publisher struct {
	client *Client
}

// NewPublisher creates a publisher
func (c *Client) NewPublisher() *Publisher {
	return &Publisher{client: c}
}

// Publish publishes a message
func (p *Publisher) Publish(ctx context.Context, channel, message string) error {
	return p.client.Client.Publish(ctx, channel, message).Err()
}
// PublishJSON publishes a JSON-encoded message
func (ps *PubSub) PublishJSON(ctx context.Context, channel string, data interface{}) error {
bytes, err := json.Marshal(data)
if err != nil {
return err
}
return ps.Publish(ctx, channel, string(bytes))
}

// Receive receives a message (blocking)
func (ps *PubSub) Receive(ctx context.Context) (*redis.Message, error) {
if ps.pubsub == nil {
return nil, nil
}
msg, err := ps.pubsub.Receive(ctx)
if err != nil {
return nil, err
}
if redisMsg, ok := msg.(*redis.Message); ok {
return redisMsg, nil
}
return nil, nil
}
