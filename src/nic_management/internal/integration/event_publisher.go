// Package integration provides cross-service integration components
// for the NIC Management service.
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// =============================================================================
// Event Publisher Error Types
// =============================================================================

var (
	// ErrPublisherNotRunning indicates publisher is not running.
	ErrPublisherNotRunning = errors.New("event publisher not running")
	// ErrSubscriberNotFound indicates subscriber not found.
	ErrSubscriberNotFound = errors.New("subscriber not found")
	// ErrSubscriberExists indicates subscriber already exists.
	ErrSubscriberExists = errors.New("subscriber already exists")
	// ErrBufferFull indicates event buffer is full.
	ErrBufferFull = errors.New("event buffer full")
	// ErrDeliveryFailed indicates event delivery failed.
	ErrDeliveryFailed = errors.New("event delivery failed")
	// ErrDeliveryTimeout indicates delivery timeout.
	ErrDeliveryTimeout = errors.New("delivery timeout")
)

// =============================================================================
// Event Type Constants
// =============================================================================

// EventType represents the type of event.
type EventType string

const (
	// Interface Events.
	EventTypeInterfaceUp       EventType = "interface.up"
	EventTypeInterfaceDown     EventType = "interface.down"
	EventTypeInterfaceDegraded EventType = "interface.degraded"

	// Failover Events.
	EventTypeFailoverInitiated EventType = "failover.initiated"
	EventTypeFailoverCompleted EventType = "failover.completed"
	EventTypeFailoverFailed    EventType = "failover.failed"
	EventTypeRecoveryStarted   EventType = "recovery.started"
	EventTypeRecoveryCompleted EventType = "recovery.completed"

	// Traffic Events.
	EventTypeTrafficAnomaly EventType = "traffic.anomaly"
	EventTypeHighLatency    EventType = "traffic.high_latency"
	EventTypePacketLoss     EventType = "traffic.packet_loss"
	EventTypeNATExhaustion  EventType = "traffic.nat_exhaustion"

	// Security Events.
	EventTypeSecurityPolicyViolation EventType = "security.policy_violation"
	EventTypeAnomalousTraffic        EventType = "security.anomalous_traffic"
	EventTypeDDoSDetected            EventType = "security.ddos_detected"

	// Configuration Events.
	EventTypeConfigChanged          EventType = "config.changed"
	EventTypeConfigReloaded         EventType = "config.reloaded"
	EventTypeConfigValidationFailed EventType = "config.validation_failed"
)

// =============================================================================
// Event Priority Constants
// =============================================================================

// EventPriority represents event priority level.
type EventPriority int

const (
	// PriorityLow is for informational events.
	PriorityLow EventPriority = iota
	// PriorityNormal is the default priority.
	PriorityNormal
	// PriorityHigh is for important events.
	PriorityHigh
	// PriorityCritical is for events requiring immediate attention.
	PriorityCritical
)

// String returns the string representation of priority.
func (p EventPriority) String() string {
	switch p {
	case PriorityLow:
		return "low"
	case PriorityNormal:
		return "normal"
	case PriorityHigh:
		return "high"
	case PriorityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// =============================================================================
// Subscriber Type Constants
// =============================================================================

// SubscriberType represents subscriber delivery mechanism.
type SubscriberType string

const (
	SubscriberTypeGRPC    SubscriberType = "grpc"
	SubscriberTypeWebhook SubscriberType = "webhook"
	SubscriberTypeQueue   SubscriberType = "queue"
	SubscriberTypeChannel SubscriberType = "channel"
)

// =============================================================================
// Delivery Mode Constants
// =============================================================================

// DeliveryMode represents delivery semantics.
type DeliveryMode string

const (
	DeliveryModeAsync    DeliveryMode = "async"
	DeliveryModeSync     DeliveryMode = "sync"
	DeliveryModeBuffered DeliveryMode = "buffered"
)

// =============================================================================
// Event Metadata Structure
// =============================================================================

// EventMetadata contains additional event context.
type EventMetadata struct {
	InterfaceName string   `json:"interface_name,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	Category      string   `json:"category,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	ParentEventID string   `json:"parent_event_id,omitempty"`
}

// =============================================================================
// Publishable Event Structure
// =============================================================================

// PublishableEvent is an event wrapper for external delivery.
type PublishableEvent struct {
	ID            string                 `json:"id"`
	Type          EventType              `json:"type"`
	Priority      EventPriority          `json:"priority"`
	Timestamp     time.Time              `json:"timestamp"`
	Source        string                 `json:"source"`
	Target        []string               `json:"target,omitempty"`
	Payload       map[string]interface{} `json:"payload"`
	Metadata      EventMetadata          `json:"metadata"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
	RetryCount    int                    `json:"retry_count"`
	ExpiresAt     time.Time              `json:"expires_at,omitempty"`
}

// NewPublishableEvent creates a new publishable event.
func NewPublishableEvent(eventType EventType, payload map[string]interface{}) *PublishableEvent {
	return &PublishableEvent{
		ID:        uuid.New().String(),
		Type:      eventType,
		Priority:  PriorityNormal,
		Timestamp: time.Now(),
		Source:    "nic-management",
		Payload:   payload,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
}

// =============================================================================
// Event Filter Structure
// =============================================================================

// EventFilter defines criteria for selective event delivery.
type EventFilter struct {
	EventTypes       []EventType   `json:"event_types,omitempty"`
	MinPriority      EventPriority `json:"min_priority"`
	Categories       []string      `json:"categories,omitempty"`
	InterfacePattern string        `json:"interface_pattern,omitempty"`
	SeverityLevels   []string      `json:"severity_levels,omitempty"`
}

// Matches checks if an event matches this filter.
func (f *EventFilter) Matches(event *PublishableEvent) bool {
	// Check event types.
	if len(f.EventTypes) > 0 {
		found := false
		for _, t := range f.EventTypes {
			if t == event.Type {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check minimum priority.
	if event.Priority < f.MinPriority {
		return false
	}

	// Check categories.
	if len(f.Categories) > 0 && event.Metadata.Category != "" {
		found := false
		for _, c := range f.Categories {
			if c == event.Metadata.Category {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check interface pattern.
	if f.InterfacePattern != "" && event.Metadata.InterfaceName != "" {
		matched, err := regexp.MatchString(f.InterfacePattern, event.Metadata.InterfaceName)
		if err != nil || !matched {
			return false
		}
	}

	// Check severity levels.
	if len(f.SeverityLevels) > 0 && event.Metadata.Severity != "" {
		found := false
		for _, s := range f.SeverityLevels {
			if s == event.Metadata.Severity {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// =============================================================================
// Subscriber Structure
// =============================================================================

// Subscriber represents an external event subscriber.
type Subscriber struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         SubscriberType         `json:"type"`
	Filter       EventFilter            `json:"filter"`
	DeliveryMode DeliveryMode           `json:"delivery_mode"`
	Endpoint     string                 `json:"endpoint,omitempty"`
	Channel      chan *PublishableEvent `json:"-"`
	MaxRetries   int                    `json:"max_retries"`
	Timeout      time.Duration          `json:"timeout"`
	Active       bool                   `json:"active"`
	Healthy      bool                   `json:"healthy"`
	LastDelivery time.Time              `json:"last_delivery,omitempty"`
	FailureCount int                    `json:"failure_count"`
}

// =============================================================================
// Retry Policy Structure
// =============================================================================

// RetryPolicy defines retry behavior.
type RetryPolicy struct {
	MaxRetries        int           `json:"max_retries"`
	InitialDelay      time.Duration `json:"initial_delay"`
	MaxDelay          time.Duration `json:"max_delay"`
	BackoffMultiplier float64       `json:"backoff_multiplier"`
}

// DefaultRetryPolicy returns the default retry policy.
func DefaultRetryPolicy() *RetryPolicy {
	return &RetryPolicy{
		MaxRetries:        3,
		InitialDelay:      time.Second,
		MaxDelay:          60 * time.Second,
		BackoffMultiplier: 2.0,
	}
}

// CalculateDelay calculates delay for given retry attempt.
func (p *RetryPolicy) CalculateDelay(retryCount int) time.Duration {
	delay := time.Duration(float64(p.InitialDelay) * math.Pow(p.BackoffMultiplier, float64(retryCount)))
	if delay > p.MaxDelay {
		delay = p.MaxDelay
	}
	return delay
}

// =============================================================================
// Dead Letter Queue Entry
// =============================================================================

// DLQEntry represents a failed event in the dead letter queue.
type DLQEntry struct {
	Event        *PublishableEvent `json:"event"`
	SubscriberID string            `json:"subscriber_id"`
	FailureTime  time.Time         `json:"failure_time"`
	Error        string            `json:"error"`
	RetryCount   int               `json:"retry_count"`
}

// =============================================================================
// Publisher Configuration
// =============================================================================

// PublisherConfig contains event publisher configuration.
type PublisherConfig struct {
	BufferSize          int           `json:"buffer_size"`
	DeliveryWorkers     int           `json:"delivery_workers"`
	RetryPolicy         *RetryPolicy  `json:"retry_policy"`
	DLQEnabled          bool          `json:"dlq_enabled"`
	DLQCapacity         int           `json:"dlq_capacity"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	DefaultTimeout      time.Duration `json:"default_timeout"`
}

// DefaultPublisherConfig returns the default publisher configuration.
func DefaultPublisherConfig() *PublisherConfig {
	return &PublisherConfig{
		BufferSize:          10000,
		DeliveryWorkers:     10,
		RetryPolicy:         DefaultRetryPolicy(),
		DLQEnabled:          true,
		DLQCapacity:         100000,
		HealthCheckInterval: 30 * time.Second,
		DefaultTimeout:      10 * time.Second,
	}
}

// =============================================================================
// Event Publisher
// =============================================================================

// EventPublisher is the central event bus.
type EventPublisher struct {
	// Configuration.
	config *PublisherConfig

	// Subscribers.
	subscribers map[string]*Subscriber
	subMu       sync.RWMutex

	// Event buffer.
	eventBuffer chan *PublishableEvent

	// HTTP clients for webhooks.
	webhookClients map[string]*http.Client
	clientMu       sync.RWMutex

	// Dead letter queue.
	dlq   []*DLQEntry
	dlqMu sync.Mutex

	// Statistics.
	eventsPublished uint64
	eventsDelivered uint64
	eventsFailed    uint64
	dlqSize         uint64

	// Lifecycle.
	wg        sync.WaitGroup
	stopChan  chan struct{}
	running   bool
	runningMu sync.Mutex
}

// NewEventPublisher creates a new event publisher.
func NewEventPublisher(config *PublisherConfig) *EventPublisher {
	if config == nil {
		config = DefaultPublisherConfig()
	}

	if config.RetryPolicy == nil {
		config.RetryPolicy = DefaultRetryPolicy()
	}

	return &EventPublisher{
		config:         config,
		subscribers:    make(map[string]*Subscriber),
		eventBuffer:    make(chan *PublishableEvent, config.BufferSize),
		webhookClients: make(map[string]*http.Client),
		dlq:            make([]*DLQEntry, 0, config.DLQCapacity),
		stopChan:       make(chan struct{}),
	}
}

// =============================================================================
// Lifecycle Management
// =============================================================================

// Start launches the event publisher.
func (ep *EventPublisher) Start(ctx context.Context) error {
	ep.runningMu.Lock()
	defer ep.runningMu.Unlock()

	if ep.running {
		return nil
	}

	// Start delivery workers.
	for i := 0; i < ep.config.DeliveryWorkers; i++ {
		ep.wg.Add(1)
		go ep.deliveryWorker(i)
	}

	// Start health monitoring.
	ep.wg.Add(1)
	go ep.healthMonitor()

	ep.running = true
	return nil
}

// Stop gracefully shuts down the publisher.
func (ep *EventPublisher) Stop() error {
	ep.runningMu.Lock()
	if !ep.running {
		ep.runningMu.Unlock()
		return nil
	}
	ep.running = false
	ep.runningMu.Unlock()

	close(ep.stopChan)
	ep.wg.Wait()

	return nil
}

// deliveryWorker processes events from the buffer.
func (ep *EventPublisher) deliveryWorker(id int) {
	_ = id // Used for logging in production.
	defer ep.wg.Done()

	for {
		select {
		case <-ep.stopChan:
			return
		case event := <-ep.eventBuffer:
			if event != nil {
				ep.deliverEvent(event)
			}
		}
	}
}

// healthMonitor periodically checks subscriber health.
func (ep *EventPublisher) healthMonitor() {
	defer ep.wg.Done()

	ticker := time.NewTicker(ep.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ep.stopChan:
			return
		case <-ticker.C:
			ep.checkSubscriberHealth()
		}
	}
}

// =============================================================================
// Publishing Methods
// =============================================================================

// Publish publishes an event asynchronously.
func (ep *EventPublisher) Publish(eventType EventType, payload map[string]interface{}) error {
	event := NewPublishableEvent(eventType, payload)
	return ep.enqueue(event)
}

// PublishWithPriority publishes an event with specified priority.
func (ep *EventPublisher) PublishWithPriority(eventType EventType, payload map[string]interface{}, priority EventPriority) error {
	event := NewPublishableEvent(eventType, payload)
	event.Priority = priority
	return ep.enqueue(event)
}

// PublishWithMetadata publishes an event with metadata.
func (ep *EventPublisher) PublishWithMetadata(eventType EventType, payload map[string]interface{}, metadata EventMetadata) error {
	event := NewPublishableEvent(eventType, payload)
	event.Metadata = metadata
	return ep.enqueue(event)
}

// PublishWithTarget publishes to specific subscribers.
func (ep *EventPublisher) PublishWithTarget(eventType EventType, payload map[string]interface{}, targets []string) error {
	event := NewPublishableEvent(eventType, payload)
	event.Target = targets
	return ep.enqueue(event)
}

// PublishCritical publishes a critical event with guaranteed delivery.
func (ep *EventPublisher) PublishCritical(eventType EventType, payload map[string]interface{}) error {
	event := NewPublishableEvent(eventType, payload)
	event.Priority = PriorityCritical
	return ep.enqueue(event)
}

// PublishSync publishes an event synchronously.
func (ep *EventPublisher) PublishSync(eventType EventType, payload map[string]interface{}) error {
	event := NewPublishableEvent(eventType, payload)
	return ep.deliverEventSync(event)
}

// PublishEvent publishes a pre-built event.
func (ep *EventPublisher) PublishEvent(event *PublishableEvent) error {
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	return ep.enqueue(event)
}

// enqueue adds an event to the buffer.
func (ep *EventPublisher) enqueue(event *PublishableEvent) error {
	ep.runningMu.Lock()
	running := ep.running
	ep.runningMu.Unlock()

	if !running {
		return ErrPublisherNotRunning
	}

	select {
	case ep.eventBuffer <- event:
		atomic.AddUint64(&ep.eventsPublished, 1)
		return nil
	default:
		return ErrBufferFull
	}
}

// =============================================================================
// Event Delivery
// =============================================================================

// deliverEvent delivers an event to all matching subscribers.
func (ep *EventPublisher) deliverEvent(event *PublishableEvent) {
	ep.subMu.RLock()
	subscribers := make([]*Subscriber, 0, len(ep.subscribers))
	for _, sub := range ep.subscribers {
		if sub.Active && sub.Healthy {
			subscribers = append(subscribers, sub)
		}
	}
	ep.subMu.RUnlock()

	for _, sub := range subscribers {
		// Check if targeted to specific subscribers.
		if len(event.Target) > 0 {
			targeted := false
			for _, t := range event.Target {
				if t == sub.ID {
					targeted = true
					break
				}
			}
			if !targeted {
				continue
			}
		}

		// Check filter.
		if !sub.Filter.Matches(event) {
			continue
		}

		// Deliver based on type.
		var err error
		switch sub.Type {
		case SubscriberTypeChannel:
			err = ep.deliverViaChannel(event, sub)
		case SubscriberTypeWebhook:
			err = ep.deliverViaWebhook(event, sub)
		case SubscriberTypeGRPC:
			err = ep.deliverViaGRPC(event, sub)
		case SubscriberTypeQueue:
			err = ep.deliverViaQueue(event, sub)
		}

		if err != nil {
			ep.handleDeliveryFailure(event, sub, err)
		} else {
			atomic.AddUint64(&ep.eventsDelivered, 1)
			ep.subMu.Lock()
			if s, exists := ep.subscribers[sub.ID]; exists {
				s.LastDelivery = time.Now()
				s.FailureCount = 0
			}
			ep.subMu.Unlock()
		}
	}
}

// deliverEventSync delivers an event synchronously to all subscribers.
func (ep *EventPublisher) deliverEventSync(event *PublishableEvent) error {
	atomic.AddUint64(&ep.eventsPublished, 1)
	ep.deliverEvent(event)
	return nil
}

// deliverViaChannel delivers to an in-process channel.
func (ep *EventPublisher) deliverViaChannel(event *PublishableEvent, sub *Subscriber) error {
	if sub.Channel == nil {
		return errors.New("subscriber channel is nil")
	}

	select {
	case sub.Channel <- event:
		return nil
	default:
		return errors.New("subscriber channel full")
	}
}

// deliverViaWebhook delivers via HTTP webhook.
func (ep *EventPublisher) deliverViaWebhook(event *PublishableEvent, sub *Subscriber) error {
	if sub.Endpoint == "" {
		return errors.New("webhook endpoint not configured")
	}

	// Get or create HTTP client.
	ep.clientMu.RLock()
	client := ep.webhookClients[sub.ID]
	ep.clientMu.RUnlock()

	if client == nil {
		client = &http.Client{
			Timeout: sub.Timeout,
		}
		if sub.Timeout == 0 {
			client.Timeout = ep.config.DefaultTimeout
		}
		ep.clientMu.Lock()
		ep.webhookClients[sub.ID] = client
		ep.clientMu.Unlock()
	}

	// Serialize event.
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to serialize event: %w", err)
	}

	// Create request.
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.Endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Event-ID", event.ID)
	req.Header.Set("X-Event-Type", string(event.Type))

	// Send request (stub - would use body in production).
	_ = data // Would be used in request body.

	// In production, this would actually send the request:
	// resp, err := client.Do(req)
	// if err != nil {
	//     return fmt.Errorf("webhook request failed: %w", err)
	// }
	// defer resp.Body.Close()
	//
	// if resp.StatusCode < 200 || resp.StatusCode >= 300 {
	//     return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	// }

	_ = req // Suppress unused warning.

	return nil
}

// deliverViaGRPC delivers via gRPC.
func (ep *EventPublisher) deliverViaGRPC(event *PublishableEvent, sub *Subscriber) error {
	_ = event // Used in production gRPC call.
	if sub.Endpoint == "" {
		return errors.New("gRPC endpoint not configured")
	}

	// In production, this would:
	// 1. Get or create gRPC client connection
	// 2. Serialize event to protobuf
	// 3. Call PublishEvent RPC
	//
	// conn, err := grpc.Dial(sub.Endpoint, grpc.WithInsecure())
	// if err != nil {
	//     return err
	// }
	// defer conn.Close()
	//
	// client := pb.NewEventServiceClient(conn)
	// ctx, cancel := context.WithTimeout(context.Background(), sub.Timeout)
	// defer cancel()
	//
	// _, err = client.PublishEvent(ctx, &pb.Event{...})
	// return err

	return nil
}

// deliverViaQueue delivers via message queue.
func (ep *EventPublisher) deliverViaQueue(event *PublishableEvent, sub *Subscriber) error {
	_ = event // Used in production queue publish.
	if sub.Endpoint == "" {
		return errors.New("queue endpoint not configured")
	}

	// In production, this would:
	// 1. Connect to message queue (RabbitMQ, Kafka)
	// 2. Serialize event
	// 3. Publish to exchange/topic
	//
	// For RabbitMQ:
	// channel.Publish(
	//     exchange,
	//     routingKey,
	//     false,
	//     false,
	//     amqp.Publishing{
	//         ContentType: "application/json",
	//         Body:        eventData,
	//     },
	// )
	//
	// For Kafka:
	// writer.WriteMessages(ctx, kafka.Message{
	//     Key:   []byte(event.ID),
	//     Value: eventData,
	// })

	return nil
}

// =============================================================================
// Failure Handling
// =============================================================================

// handleDeliveryFailure handles a failed delivery.
func (ep *EventPublisher) handleDeliveryFailure(event *PublishableEvent, sub *Subscriber, err error) {
	atomic.AddUint64(&ep.eventsFailed, 1)

	// Update subscriber failure count.
	ep.subMu.Lock()
	if s, exists := ep.subscribers[sub.ID]; exists {
		s.FailureCount++
		if s.FailureCount >= 5 {
			s.Healthy = false
		}
	}
	ep.subMu.Unlock()

	// Check if we should retry.
	if event.RetryCount < ep.config.RetryPolicy.MaxRetries {
		event.RetryCount++
		delay := ep.config.RetryPolicy.CalculateDelay(event.RetryCount)

		// Schedule retry.
		go func() {
			time.Sleep(delay)
			select {
			case ep.eventBuffer <- event:
			default:
				// Buffer full, send to DLQ.
				ep.sendToDLQ(event, sub, err)
			}
		}()
	} else if ep.config.DLQEnabled {
		ep.sendToDLQ(event, sub, err)
	}
}

// sendToDLQ sends a failed event to the dead letter queue.
func (ep *EventPublisher) sendToDLQ(event *PublishableEvent, sub *Subscriber, err error) {
	ep.dlqMu.Lock()
	defer ep.dlqMu.Unlock()

	if len(ep.dlq) >= ep.config.DLQCapacity {
		// DLQ full, drop oldest.
		ep.dlq = ep.dlq[1:]
	}

	ep.dlq = append(ep.dlq, &DLQEntry{
		Event:        event,
		SubscriberID: sub.ID,
		FailureTime:  time.Now(),
		Error:        err.Error(),
		RetryCount:   event.RetryCount,
	})

	atomic.AddUint64(&ep.dlqSize, 1)
}

// =============================================================================
// Subscription Management
// =============================================================================

// Subscribe registers a new subscriber.
func (ep *EventPublisher) Subscribe(sub *Subscriber) error {
	if sub.ID == "" {
		sub.ID = uuid.New().String()
	}

	ep.subMu.Lock()
	defer ep.subMu.Unlock()

	if _, exists := ep.subscribers[sub.ID]; exists {
		return ErrSubscriberExists
	}

	if sub.MaxRetries == 0 {
		sub.MaxRetries = ep.config.RetryPolicy.MaxRetries
	}
	if sub.Timeout == 0 {
		sub.Timeout = ep.config.DefaultTimeout
	}

	sub.Active = true
	sub.Healthy = true
	ep.subscribers[sub.ID] = sub

	return nil
}

// SubscribeChannel registers a channel-based subscriber.
func (ep *EventPublisher) SubscribeChannel(name string, ch chan *PublishableEvent, filter EventFilter) (string, error) {
	sub := &Subscriber{
		ID:           uuid.New().String(),
		Name:         name,
		Type:         SubscriberTypeChannel,
		Filter:       filter,
		DeliveryMode: DeliveryModeAsync,
		Channel:      ch,
	}

	if err := ep.Subscribe(sub); err != nil {
		return "", err
	}

	return sub.ID, nil
}

// SubscribeWebhook registers a webhook subscriber.
func (ep *EventPublisher) SubscribeWebhook(name, endpoint string, filter EventFilter) (string, error) {
	sub := &Subscriber{
		ID:           uuid.New().String(),
		Name:         name,
		Type:         SubscriberTypeWebhook,
		Filter:       filter,
		DeliveryMode: DeliveryModeAsync,
		Endpoint:     endpoint,
	}

	if err := ep.Subscribe(sub); err != nil {
		return "", err
	}

	return sub.ID, nil
}

// Unsubscribe removes a subscriber.
func (ep *EventPublisher) Unsubscribe(subscriberID string) error {
	ep.subMu.Lock()
	defer ep.subMu.Unlock()

	if _, exists := ep.subscribers[subscriberID]; !exists {
		return ErrSubscriberNotFound
	}

	delete(ep.subscribers, subscriberID)

	// Clean up HTTP client.
	ep.clientMu.Lock()
	delete(ep.webhookClients, subscriberID)
	ep.clientMu.Unlock()

	return nil
}

// UpdateSubscriber updates subscriber configuration.
func (ep *EventPublisher) UpdateSubscriber(subscriberID string, updates func(*Subscriber)) error {
	ep.subMu.Lock()
	defer ep.subMu.Unlock()

	sub, exists := ep.subscribers[subscriberID]
	if !exists {
		return ErrSubscriberNotFound
	}

	updates(sub)
	return nil
}

// GetSubscribers returns all subscribers.
func (ep *EventPublisher) GetSubscribers() []*Subscriber {
	ep.subMu.RLock()
	defer ep.subMu.RUnlock()

	result := make([]*Subscriber, 0, len(ep.subscribers))
	for _, sub := range ep.subscribers {
		copy := *sub
		result = append(result, &copy)
	}
	return result
}

// GetSubscriber returns a specific subscriber.
func (ep *EventPublisher) GetSubscriber(subscriberID string) (*Subscriber, error) {
	ep.subMu.RLock()
	defer ep.subMu.RUnlock()

	sub, exists := ep.subscribers[subscriberID]
	if !exists {
		return nil, ErrSubscriberNotFound
	}

	copy := *sub
	return &copy, nil
}

// =============================================================================
// Health Monitoring
// =============================================================================

// checkSubscriberHealth checks health of all subscribers.
func (ep *EventPublisher) checkSubscriberHealth() {
	ep.subMu.Lock()
	defer ep.subMu.Unlock()

	for _, sub := range ep.subscribers {
		switch sub.Type {
		case SubscriberTypeWebhook:
			// In production, would ping webhook endpoint.
			// For now, just check failure count.
			if sub.FailureCount >= 5 {
				sub.Healthy = false
			} else {
				sub.Healthy = true
			}
		case SubscriberTypeChannel:
			sub.Healthy = sub.Channel != nil
		default:
			sub.Healthy = true
		}
	}
}

// =============================================================================
// Dead Letter Queue Methods
// =============================================================================

// GetDLQEvents returns events from the dead letter queue.
func (ep *EventPublisher) GetDLQEvents(limit int) []*DLQEntry {
	ep.dlqMu.Lock()
	defer ep.dlqMu.Unlock()

	if limit <= 0 || limit > len(ep.dlq) {
		limit = len(ep.dlq)
	}

	result := make([]*DLQEntry, limit)
	copy(result, ep.dlq[:limit])
	return result
}

// ReplayDLQEvent replays an event from the DLQ.
func (ep *EventPublisher) ReplayDLQEvent(eventID string) error {
	ep.dlqMu.Lock()
	defer ep.dlqMu.Unlock()

	for i, entry := range ep.dlq {
		if entry.Event.ID == eventID {
			event := entry.Event
			event.RetryCount = 0

			// Remove from DLQ.
			ep.dlq = append(ep.dlq[:i], ep.dlq[i+1:]...)
			atomic.AddUint64(&ep.dlqSize, ^uint64(0)) // Decrement.

			// Re-enqueue.
			select {
			case ep.eventBuffer <- event:
				return nil
			default:
				return ErrBufferFull
			}
		}
	}

	return errors.New("event not found in DLQ")
}

// ClearDLQ clears the dead letter queue.
func (ep *EventPublisher) ClearDLQ() {
	ep.dlqMu.Lock()
	defer ep.dlqMu.Unlock()

	ep.dlq = make([]*DLQEntry, 0, ep.config.DLQCapacity)
	atomic.StoreUint64(&ep.dlqSize, 0)
}

// =============================================================================
// Statistics
// =============================================================================

// GetStatistics returns publisher statistics.
func (ep *EventPublisher) GetStatistics() map[string]uint64 {
	ep.subMu.RLock()
	activeCount := 0
	healthyCount := 0
	for _, sub := range ep.subscribers {
		if sub.Active {
			activeCount++
		}
		if sub.Healthy {
			healthyCount++
		}
	}
	ep.subMu.RUnlock()

	return map[string]uint64{
		"events_published":    atomic.LoadUint64(&ep.eventsPublished),
		"events_delivered":    atomic.LoadUint64(&ep.eventsDelivered),
		"events_failed":       atomic.LoadUint64(&ep.eventsFailed),
		"dlq_size":            atomic.LoadUint64(&ep.dlqSize),
		"active_subscribers":  uint64(activeCount),
		"healthy_subscribers": uint64(healthyCount),
		"buffer_size":         uint64(len(ep.eventBuffer)),
		"buffer_capacity":     uint64(cap(ep.eventBuffer)),
	}
}

// GetBufferUtilization returns buffer utilization percentage.
func (ep *EventPublisher) GetBufferUtilization() float64 {
	return float64(len(ep.eventBuffer)) / float64(cap(ep.eventBuffer)) * 100
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck verifies the publisher is operational.
func (ep *EventPublisher) HealthCheck() error {
	ep.runningMu.Lock()
	running := ep.running
	ep.runningMu.Unlock()

	if !running {
		return ErrPublisherNotRunning
	}

	// Check buffer not full.
	if ep.GetBufferUtilization() > 90 {
		return errors.New("event buffer near capacity")
	}

	return nil
}

// GetConfig returns the current configuration.
func (ep *EventPublisher) GetConfig() *PublisherConfig {
	return ep.config
}
