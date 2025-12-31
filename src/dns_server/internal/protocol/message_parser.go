// Package protocol implements DNS wire format parsing and serialization (RFC 1035).
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// ============================================================================
// DNS Message Parser
// ============================================================================

// MessageParser converts binary DNS packets to structured messages
type MessageParser struct {
	data           []byte
	offset         int
	compressionMap map[int]string
}

// ParseDNSPacket parses a raw DNS packet into a Message struct
func ParseDNSPacket(packet []byte) (*Message, error) {
	parser := &MessageParser{
		data:           packet,
		offset:         0,
		compressionMap: make(map[int]string),
	}
	return parser.ParseMessage()
}

// ParseMessage parses the DNS message from the parser's data buffer
func (p *MessageParser) ParseMessage() (*Message, error) {
	// Minimum DNS header is 12 bytes
	if len(p.data) < 12 {
		return nil, errors.New("packet too short: minimum 12 bytes required")
	}

	msg := &Message{
		Questions:  make([]Question, 0),
		Answers:    make([]ResourceRecord, 0),
		Authority:  make([]ResourceRecord, 0),
		Additional: make([]ResourceRecord, 0),
	}

	// Parse header
	msg.ID = binary.BigEndian.Uint16(p.data[0:2])
	msg.Flags.FromUint16(binary.BigEndian.Uint16(p.data[2:4]))
	qdcount := binary.BigEndian.Uint16(p.data[4:6])
	ancount := binary.BigEndian.Uint16(p.data[6:8])
	nscount := binary.BigEndian.Uint16(p.data[8:10])
	arcount := binary.BigEndian.Uint16(p.data[10:12])
	p.offset = 12

	// Parse questions
	for i := uint16(0); i < qdcount; i++ {
		q, err := p.parseQuestion()
		if err != nil {
			return nil, fmt.Errorf("failed to parse question %d: %w", i+1, err)
		}
		msg.Questions = append(msg.Questions, q)
	}

	// Parse answers
	for i := uint16(0); i < ancount; i++ {
		rr, err := p.parseResourceRecord()
		if err != nil {
			return nil, fmt.Errorf("failed to parse answer %d: %w", i+1, err)
		}
		msg.Answers = append(msg.Answers, rr)
	}

	// Parse authority records
	for i := uint16(0); i < nscount; i++ {
		rr, err := p.parseResourceRecord()
		if err != nil {
			return nil, fmt.Errorf("failed to parse authority %d: %w", i+1, err)
		}
		msg.Authority = append(msg.Authority, rr)
	}

	// Parse additional records
	for i := uint16(0); i < arcount; i++ {
		rr, err := p.parseResourceRecord()
		if err != nil {
			return nil, fmt.Errorf("failed to parse additional %d: %w", i+1, err)
		}
		msg.Additional = append(msg.Additional, rr)
	}

	return msg, nil
}

func (p *MessageParser) parseQuestion() (Question, error) {
	name, err := p.parseDomainName()
	if err != nil {
		return Question{}, err
	}

	if p.offset+4 > len(p.data) {
		return Question{}, errors.New("truncated question section")
	}

	qtype := RecordType(binary.BigEndian.Uint16(p.data[p.offset : p.offset+2]))
	qclass := Class(binary.BigEndian.Uint16(p.data[p.offset+2 : p.offset+4]))
	p.offset += 4

	return Question{Name: name, Type: qtype, Class: qclass}, nil
}

func (p *MessageParser) parseResourceRecord() (ResourceRecord, error) {
	name, err := p.parseDomainName()
	if err != nil {
		return ResourceRecord{}, err
	}

	if p.offset+10 > len(p.data) {
		return ResourceRecord{}, errors.New("truncated resource record header")
	}

	rtype := RecordType(binary.BigEndian.Uint16(p.data[p.offset : p.offset+2]))
	rclass := Class(binary.BigEndian.Uint16(p.data[p.offset+2 : p.offset+4]))
	ttl := binary.BigEndian.Uint32(p.data[p.offset+4 : p.offset+8])
	rdlength := binary.BigEndian.Uint16(p.data[p.offset+8 : p.offset+10])
	p.offset += 10

	if p.offset+int(rdlength) > len(p.data) {
		return ResourceRecord{}, errors.New("truncated RDATA")
	}

	rdata := make([]byte, rdlength)
	copy(rdata, p.data[p.offset:p.offset+int(rdlength)])
	p.offset += int(rdlength)

	rr := ResourceRecord{
		Name:  name,
		Type:  rtype,
		Class: rclass,
		TTL:   ttl,
		RData: rdata,
	}

	// Parse RDATA based on type
	rr.ParsedData = p.parseRData(rtype, rdata)

	return rr, nil
}

func (p *MessageParser) parseDomainName() (string, error) {
	var labels []string
	maxJumps := 10
	jumped := false
	savedOffset := 0

	for maxJumps > 0 {
		if p.offset >= len(p.data) {
			return "", errors.New("domain name extends past packet end")
		}

		length := int(p.data[p.offset])

		// Check for pointer compression
		if length&0xC0 == 0xC0 {
			if p.offset+1 >= len(p.data) {
				return "", errors.New("incomplete compression pointer")
			}
			pointer := int(p.data[p.offset]&0x3F)<<8 | int(p.data[p.offset+1])
			if !jumped {
				savedOffset = p.offset + 2
			}
			p.offset = pointer
			jumped = true
			maxJumps--
			continue
		}

		// End of name
		if length == 0 {
			p.offset++
			if jumped {
				p.offset = savedOffset
			}
			break
		}

		// Regular label
		if length > 63 {
			return "", fmt.Errorf("invalid label length: %d", length)
		}
		p.offset++
		if p.offset+length > len(p.data) {
			return "", errors.New("label extends past packet end")
		}
		labels = append(labels, string(p.data[p.offset:p.offset+length]))
		p.offset += length
	}

	if maxJumps == 0 {
		return "", errors.New("too many compression pointers")
	}

	return strings.Join(labels, "."), nil
}

func (p *MessageParser) parseRData(rtype RecordType, rdata []byte) interface{} {
	switch rtype {
	case TypeA:
		if len(rdata) >= 4 {
			return net.IP(rdata[:4])
		}
	case TypeAAAA:
		if len(rdata) >= 16 {
			return net.IP(rdata[:16])
		}
	case TypeCNAME, TypeNS, TypePTR:
		name, _, _ := decodeDomainName(rdata, 0)
		return name
	case TypeMX:
		if len(rdata) >= 3 {
			priority := binary.BigEndian.Uint16(rdata[:2])
			mailserver, _, _ := decodeDomainName(rdata, 2)
			return &MXRecord{Priority: priority, MailServer: mailserver}
		}
	case TypeTXT:
		var texts []string
		offset := 0
		for offset < len(rdata) {
			length := int(rdata[offset])
			offset++
			if offset+length <= len(rdata) {
				texts = append(texts, string(rdata[offset:offset+length]))
				offset += length
			} else {
				break
			}
		}
		return texts
	case TypeSRV:
		if len(rdata) >= 7 {
			priority := binary.BigEndian.Uint16(rdata[:2])
			weight := binary.BigEndian.Uint16(rdata[2:4])
			port := binary.BigEndian.Uint16(rdata[4:6])
			target, _, _ := decodeDomainName(rdata, 6)
			return &SRVRecord{Priority: priority, Weight: weight, Port: port, Target: target}
		}
	}
	return nil
}

// ============================================================================
// DNS Message Serializer
// ============================================================================

// MessageSerializer converts structured messages to binary DNS packets
type MessageSerializer struct {
	buffer         []byte
	compressionMap map[string]int
}

// SerializeDNSMessage converts a Message to wire format bytes
func SerializeDNSMessage(msg *Message) ([]byte, error) {
	s := &MessageSerializer{
		buffer:         make([]byte, 0, 512),
		compressionMap: make(map[string]int),
	}
	return s.Serialize(msg)
}

// Serialize converts the message to wire format
func (s *MessageSerializer) Serialize(msg *Message) ([]byte, error) {
	// Header
	s.writeUint16(msg.ID)
	s.writeUint16(msg.Flags.ToUint16())
	s.writeUint16(uint16(len(msg.Questions)))
	s.writeUint16(uint16(len(msg.Answers)))
	s.writeUint16(uint16(len(msg.Authority)))
	s.writeUint16(uint16(len(msg.Additional)))

	// Questions
	for _, q := range msg.Questions {
		s.serializeQuestion(q)
	}

	// Answers
	for _, rr := range msg.Answers {
		s.serializeResourceRecord(rr)
	}

	// Authority
	for _, rr := range msg.Authority {
		s.serializeResourceRecord(rr)
	}

	// Additional
	for _, rr := range msg.Additional {
		s.serializeResourceRecord(rr)
	}

	return s.buffer, nil
}

func (s *MessageSerializer) serializeQuestion(q Question) {
	s.serializeDomainName(q.Name)
	s.writeUint16(uint16(q.Type))
	s.writeUint16(uint16(q.Class))
}

func (s *MessageSerializer) serializeResourceRecord(rr ResourceRecord) {
	s.serializeDomainName(rr.Name)
	s.writeUint16(uint16(rr.Type))
	s.writeUint16(uint16(rr.Class))
	s.writeUint32(rr.TTL)

	// RDLENGTH placeholder position
	rdlengthPos := len(s.buffer)
	s.writeUint16(0) // Placeholder

	// Write RDATA
	rdataStart := len(s.buffer)
	s.serializeRData(rr)
	rdataLen := len(s.buffer) - rdataStart

	// Update RDLENGTH
	binary.BigEndian.PutUint16(s.buffer[rdlengthPos:rdlengthPos+2], uint16(rdataLen))
}

func (s *MessageSerializer) serializeDomainName(name string) {
	if name == "" {
		s.buffer = append(s.buffer, 0)
		return
	}

	// Check for compression opportunity
	if offset, ok := s.compressionMap[name]; ok && offset < 16384 {
		pointer := uint16(0xC000 | offset)
		s.writeUint16(pointer)
		return
	}

	// Store position for future compression
	s.compressionMap[name] = len(s.buffer)

	// Write labels
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) > 63 {
			label = label[:63]
		}
		s.buffer = append(s.buffer, byte(len(label)))
		s.buffer = append(s.buffer, []byte(label)...)
	}
	s.buffer = append(s.buffer, 0)
}

func (s *MessageSerializer) serializeRData(rr ResourceRecord) {
	switch rr.Type {
	case TypeA:
		if ip, ok := rr.ParsedData.(net.IP); ok {
			ip4 := ip.To4()
			if ip4 != nil {
				s.buffer = append(s.buffer, ip4...)
			}
		} else if len(rr.RData) >= 4 {
			s.buffer = append(s.buffer, rr.RData[:4]...)
		}

	case TypeAAAA:
		if ip, ok := rr.ParsedData.(net.IP); ok {
			ip16 := ip.To16()
			if ip16 != nil {
				s.buffer = append(s.buffer, ip16...)
			}
		} else if len(rr.RData) >= 16 {
			s.buffer = append(s.buffer, rr.RData[:16]...)
		}

	case TypeCNAME, TypeNS, TypePTR:
		if name, ok := rr.ParsedData.(string); ok {
			s.serializeDomainName(name)
		} else {
			s.buffer = append(s.buffer, rr.RData...)
		}

	case TypeMX:
		if mx, ok := rr.ParsedData.(*MXRecord); ok {
			s.writeUint16(mx.Priority)
			s.serializeDomainName(mx.MailServer)
		} else {
			s.buffer = append(s.buffer, rr.RData...)
		}

	case TypeTXT:
		if texts, ok := rr.ParsedData.([]string); ok {
			for _, txt := range texts {
				if len(txt) > 255 {
					txt = txt[:255]
				}
				s.buffer = append(s.buffer, byte(len(txt)))
				s.buffer = append(s.buffer, []byte(txt)...)
			}
		} else {
			s.buffer = append(s.buffer, rr.RData...)
		}

	case TypeSRV:
		if srv, ok := rr.ParsedData.(*SRVRecord); ok {
			s.writeUint16(srv.Priority)
			s.writeUint16(srv.Weight)
			s.writeUint16(srv.Port)
			s.serializeDomainName(srv.Target)
		} else {
			s.buffer = append(s.buffer, rr.RData...)
		}

	default:
		s.buffer = append(s.buffer, rr.RData...)
	}
}

func (s *MessageSerializer) writeUint16(v uint16) {
	s.buffer = append(s.buffer, byte(v>>8), byte(v))
}

func (s *MessageSerializer) writeUint32(v uint32) {
	s.buffer = append(s.buffer, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// ============================================================================
// Helper Functions
// ============================================================================

func decodeDomainName(data []byte, offset int) (string, int, error) {
	if offset >= len(data) {
		return "", offset, errors.New("offset beyond data length")
	}

	var labels []string
	originalOffset := offset
	jumped := false
	maxJumps := 10

	for maxJumps > 0 {
		if offset >= len(data) {
			return "", originalOffset, errors.New("unexpected end of data")
		}

		length := int(data[offset])

		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", originalOffset, errors.New("incomplete pointer")
			}
			pointer := int(data[offset]&0x3F)<<8 | int(data[offset+1])
			if !jumped {
				originalOffset = offset + 2
			}
			offset = pointer
			jumped = true
			maxJumps--
			continue
		}

		if length == 0 {
			if !jumped {
				originalOffset = offset + 1
			}
			break
		}

		offset++
		if offset+length > len(data) {
			return "", originalOffset, errors.New("label extends beyond data")
		}
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}

	if maxJumps == 0 {
		return "", originalOffset, errors.New("too many compression pointers")
	}

	return strings.Join(labels, "."), originalOffset, nil
}
