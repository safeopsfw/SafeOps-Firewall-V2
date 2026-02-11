package api

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// ============================================================================
// Ticket Model
// ============================================================================

// Ticket represents a security incident ticket.
type Ticket struct {
	ID           string       `json:"id"`
	Title        string       `json:"title"`
	Description  string       `json:"description"`
	Severity     string       `json:"severity"` // critical, high, medium, low, info
	Status       string       `json:"status"`   // open, in_progress, resolved, closed
	Assignee     string       `json:"assignee,omitempty"`
	LinkedAlerts []string     `json:"linked_alerts,omitempty"`
	LinkedIPs    []string     `json:"linked_ips,omitempty"`
	Tags         []string     `json:"tags,omitempty"`
	Notes        []TicketNote `json:"notes,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
	ResolvedAt   *time.Time   `json:"resolved_at,omitempty"`
	CreatedBy    string       `json:"created_by,omitempty"`
}

// TicketNote is a comment or update on a ticket.
type TicketNote struct {
	ID        string    `json:"id"`
	Author    string    `json:"author"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

// ============================================================================
// Ticket Store (in-memory)
// ============================================================================

// TicketStore is a thread-safe in-memory store for tickets.
type TicketStore struct {
	mu      sync.RWMutex
	tickets map[string]*Ticket
}

// NewTicketStore creates a new ticket store.
func NewTicketStore() *TicketStore {
	return &TicketStore{
		tickets: make(map[string]*Ticket),
	}
}

// Get returns a ticket by ID, or nil if not found.
func (ts *TicketStore) Get(id string) *Ticket {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	t := ts.tickets[id]
	if t == nil {
		return nil
	}
	// Return a copy to prevent races
	copy := *t
	return &copy
}

// GetAll returns all tickets, optionally filtered by status.
func (ts *TicketStore) GetAll(statusFilter string) []*Ticket {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	result := make([]*Ticket, 0, len(ts.tickets))
	for _, t := range ts.tickets {
		if statusFilter != "" && t.Status != statusFilter {
			continue
		}
		copy := *t
		result = append(result, &copy)
	}
	return result
}

// Create adds a new ticket and returns it.
func (ts *TicketStore) Create(t *Ticket) *Ticket {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	t.ID = uuid.New().String()[:8] // Short ID for readability
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()
	if t.Status == "" {
		t.Status = "open"
	}
	if t.Notes == nil {
		t.Notes = []TicketNote{}
	}
	if t.LinkedAlerts == nil {
		t.LinkedAlerts = []string{}
	}
	if t.LinkedIPs == nil {
		t.LinkedIPs = []string{}
	}
	if t.Tags == nil {
		t.Tags = []string{}
	}

	ts.tickets[t.ID] = t
	return t
}

// Update modifies an existing ticket.
func (ts *TicketStore) Update(id string, updates map[string]interface{}) (*Ticket, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	t, ok := ts.tickets[id]
	if !ok {
		return nil, fmt.Errorf("ticket %s not found", id)
	}

	if v, ok := updates["title"].(string); ok && v != "" {
		t.Title = v
	}
	if v, ok := updates["description"].(string); ok {
		t.Description = v
	}
	if v, ok := updates["severity"].(string); ok && v != "" {
		t.Severity = v
	}
	if v, ok := updates["status"].(string); ok && v != "" {
		oldStatus := t.Status
		t.Status = v
		// Track resolution time
		if (v == "resolved" || v == "closed") && oldStatus != "resolved" && oldStatus != "closed" {
			now := time.Now()
			t.ResolvedAt = &now
		}
	}
	if v, ok := updates["assignee"].(string); ok {
		t.Assignee = v
	}
	if v, ok := updates["tags"].([]interface{}); ok {
		tags := make([]string, 0, len(v))
		for _, tag := range v {
			if s, ok := tag.(string); ok {
				tags = append(tags, s)
			}
		}
		t.Tags = tags
	}
	if v, ok := updates["linked_alerts"].([]interface{}); ok {
		alerts := make([]string, 0, len(v))
		for _, a := range v {
			if s, ok := a.(string); ok {
				alerts = append(alerts, s)
			}
		}
		t.LinkedAlerts = alerts
	}
	if v, ok := updates["linked_ips"].([]interface{}); ok {
		ips := make([]string, 0, len(v))
		for _, ip := range v {
			if s, ok := ip.(string); ok {
				ips = append(ips, s)
			}
		}
		t.LinkedIPs = ips
	}

	t.UpdatedAt = time.Now()
	return t, nil
}

// Delete removes a ticket.
func (ts *TicketStore) Delete(id string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if _, ok := ts.tickets[id]; ok {
		delete(ts.tickets, id)
		return true
	}
	return false
}

// AddNote adds a note to a ticket.
func (ts *TicketStore) AddNote(id string, note TicketNote) (*Ticket, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	t, ok := ts.tickets[id]
	if !ok {
		return nil, fmt.Errorf("ticket %s not found", id)
	}

	note.ID = uuid.New().String()[:8]
	note.CreatedAt = time.Now()
	t.Notes = append(t.Notes, note)
	t.UpdatedAt = time.Now()

	copy := *t
	return &copy, nil
}

// Count returns the number of tickets, optionally filtered by status.
func (ts *TicketStore) Count(status string) int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if status == "" {
		return len(ts.tickets)
	}

	count := 0
	for _, t := range ts.tickets {
		if t.Status == status {
			count++
		}
	}
	return count
}

// ============================================================================
// Ticket API Handlers
// ============================================================================

// handleGetTickets handles GET /api/v1/tickets.
// Supports query parameters: status, severity, assignee, sort.
func (s *Server) handleGetTickets(c *fiber.Ctx) error {
	statusFilter := strings.ToLower(c.Query("status", ""))
	severityFilter := strings.ToLower(c.Query("severity", ""))
	assigneeFilter := c.Query("assignee", "")
	sortBy := c.Query("sort", "updated_at")
	sortOrder := c.Query("order", "desc")

	tickets := s.tickets.GetAll("")

	// Apply filters
	filtered := make([]*Ticket, 0, len(tickets))
	for _, t := range tickets {
		if statusFilter != "" && t.Status != statusFilter {
			continue
		}
		if severityFilter != "" && t.Severity != severityFilter {
			continue
		}
		if assigneeFilter != "" && !strings.Contains(strings.ToLower(t.Assignee), strings.ToLower(assigneeFilter)) {
			continue
		}
		filtered = append(filtered, t)
	}

	// Sort
	sort.Slice(filtered, func(i, j int) bool {
		ascending := sortOrder != "desc"
		switch sortBy {
		case "created_at":
			if ascending {
				return filtered[i].CreatedAt.Before(filtered[j].CreatedAt)
			}
			return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
		case "severity":
			si := severityOrder(filtered[i].Severity)
			sj := severityOrder(filtered[j].Severity)
			if ascending {
				return si < sj
			}
			return si > sj
		default: // updated_at
			if ascending {
				return filtered[i].UpdatedAt.Before(filtered[j].UpdatedAt)
			}
			return filtered[i].UpdatedAt.After(filtered[j].UpdatedAt)
		}
	})

	// Stats summary
	stats := map[string]int{
		"open":        s.tickets.Count("open"),
		"in_progress": s.tickets.Count("in_progress"),
		"resolved":    s.tickets.Count("resolved"),
		"closed":      s.tickets.Count("closed"),
		"total":       s.tickets.Count(""),
	}

	return c.JSON(fiber.Map{
		"tickets": filtered,
		"total":   len(filtered),
		"stats":   stats,
	})
}

// CreateTicketRequest is the request body for creating a ticket.
type CreateTicketRequest struct {
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Severity     string   `json:"severity"`
	Assignee     string   `json:"assignee,omitempty"`
	LinkedAlerts []string `json:"linked_alerts,omitempty"`
	LinkedIPs    []string `json:"linked_ips,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	CreatedBy    string   `json:"created_by,omitempty"`
}

// handleCreateTicket handles POST /api/v1/tickets.
func (s *Server) handleCreateTicket(c *fiber.Ctx) error {
	var req CreateTicketRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid request body: "+err.Error())
	}

	if req.Title == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Title is required")
	}

	// Validate severity
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	if req.Severity == "" {
		req.Severity = "medium"
	}
	if !validSeverities[req.Severity] {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			fmt.Sprintf("Invalid severity %q. Valid: critical, high, medium, low, info", req.Severity))
	}

	ticket := s.tickets.Create(&Ticket{
		Title:        req.Title,
		Description:  req.Description,
		Severity:     req.Severity,
		Assignee:     req.Assignee,
		LinkedAlerts: req.LinkedAlerts,
		LinkedIPs:    req.LinkedIPs,
		Tags:         req.Tags,
		CreatedBy:    req.CreatedBy,
	})

	s.hub.BroadcastEvent("ticket_created", map[string]interface{}{
		"id":       ticket.ID,
		"title":    ticket.Title,
		"severity": ticket.Severity,
	})

	s.logger.Info().
		Str("id", ticket.ID).
		Str("title", ticket.Title).
		Str("severity", ticket.Severity).
		Msg("Ticket created")

	return c.Status(fiber.StatusCreated).JSON(ticket)
}

// handleGetTicket handles GET /api/v1/tickets/:id.
func (s *Server) handleGetTicket(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Ticket ID is required")
	}

	ticket := s.tickets.Get(id)
	if ticket == nil {
		return respondError(c, fiber.StatusNotFound, "not_found",
			fmt.Sprintf("Ticket %s not found", id))
	}

	return c.JSON(ticket)
}

// handleUpdateTicket handles PUT /api/v1/tickets/:id.
func (s *Server) handleUpdateTicket(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Ticket ID is required")
	}

	var updates map[string]interface{}
	if err := c.BodyParser(&updates); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid request body: "+err.Error())
	}

	// Validate status if provided
	if status, ok := updates["status"].(string); ok {
		validStatuses := map[string]bool{
			"open": true, "in_progress": true, "resolved": true, "closed": true,
		}
		if !validStatuses[status] {
			return respondError(c, fiber.StatusBadRequest, "bad_request",
				fmt.Sprintf("Invalid status %q. Valid: open, in_progress, resolved, closed", status))
		}
	}

	ticket, err := s.tickets.Update(id, updates)
	if err != nil {
		return respondError(c, fiber.StatusNotFound, "not_found", err.Error())
	}

	s.hub.BroadcastEvent("ticket_updated", map[string]interface{}{
		"id":     ticket.ID,
		"status": ticket.Status,
	})

	return c.JSON(ticket)
}

// handleDeleteTicket handles DELETE /api/v1/tickets/:id.
func (s *Server) handleDeleteTicket(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Ticket ID is required")
	}

	if !s.tickets.Delete(id) {
		return respondError(c, fiber.StatusNotFound, "not_found",
			fmt.Sprintf("Ticket %s not found", id))
	}

	s.logger.Info().Str("id", id).Msg("Ticket deleted")

	return c.JSON(fiber.Map{
		"message": fmt.Sprintf("Ticket %s deleted", id),
	})
}

// AddNoteRequest is the request body for adding a note to a ticket.
type AddNoteRequest struct {
	Author  string `json:"author"`
	Content string `json:"content"`
}

// handleAddTicketNote handles POST /api/v1/tickets/:id/notes.
func (s *Server) handleAddTicketNote(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Ticket ID is required")
	}

	var req AddNoteRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "bad_request",
			"Invalid request body: "+err.Error())
	}

	if req.Content == "" {
		return respondError(c, fiber.StatusBadRequest, "bad_request", "Note content is required")
	}
	if req.Author == "" {
		req.Author = "anonymous"
	}

	ticket, err := s.tickets.AddNote(id, TicketNote{
		Author:  req.Author,
		Content: req.Content,
	})
	if err != nil {
		return respondError(c, fiber.StatusNotFound, "not_found", err.Error())
	}

	return c.Status(fiber.StatusCreated).JSON(ticket)
}

// ============================================================================
// Helpers
// ============================================================================

// severityOrder returns a numeric ordering for severity levels.
// Higher number = more severe.
func severityOrder(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
