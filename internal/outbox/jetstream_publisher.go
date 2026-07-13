package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/nats-io/nats.go/jetstream"
)

const envelopeSchema = "network-broker.outbox.v1"

type jetStreamClient interface {
	Publish(context.Context, string, []byte, ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

// JetStreamPublisher publishes versioned event envelopes and waits for a
// persistence acknowledgement from the expected JetStream stream.
type JetStreamPublisher struct {
	client  jetStreamClient
	stream  string
	subject string
}

type eventEnvelope struct {
	Schema        string          `json:"schema"`
	ID            string          `json:"id"`
	TenantID      string          `json:"tenant_id"`
	AggregateType string          `json:"aggregate_type"`
	AggregateID   string          `json:"aggregate_id"`
	Type          string          `json:"type"`
	OccurredAt    string          `json:"occurred_at"`
	Payload       json.RawMessage `json:"payload"`
}

// NewJetStreamPublisher constructs a publisher for an administratively
// provisioned stream and exact (non-wildcard) subject.
func NewJetStreamPublisher(client jetStreamClient, stream, subject string) (*JetStreamPublisher, error) {
	if client == nil {
		return nil, fmt.Errorf("jetstream client is required")
	}
	if err := validateStreamName(stream); err != nil {
		return nil, err
	}
	if err := validateSubject(subject); err != nil {
		return nil, err
	}

	return &JetStreamPublisher{client: client, stream: stream, subject: subject}, nil
}

// Publish sends an immutable envelope using the event ID as JetStream's
// server-side de-duplication identifier.
func (p *JetStreamPublisher) Publish(ctx context.Context, event Event) error {
	if p == nil || p.client == nil {
		return fmt.Errorf("jetstream publisher is not configured")
	}
	if err := event.Validate(); err != nil {
		return fmt.Errorf("validate outbox event: %w", err)
	}
	if !json.Valid(event.Payload) {
		return fmt.Errorf("outbox event %q payload is not valid JSON", event.ID)
	}
	payload, err := json.Marshal(eventEnvelope{
		Schema:        envelopeSchema,
		ID:            event.ID,
		TenantID:      event.TenantID,
		AggregateType: event.AggregateType,
		AggregateID:   event.AggregateID,
		Type:          event.Type,
		OccurredAt:    event.OccurredAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		Payload:       json.RawMessage(event.Payload),
	})
	if err != nil {
		return fmt.Errorf("encode outbox event %q: %w", event.ID, err)
	}
	ack, err := p.client.Publish(ctx, p.subject, payload,
		jetstream.WithMsgID(event.ID), jetstream.WithExpectStream(p.stream))
	if err != nil {
		return fmt.Errorf("publish outbox event %q to jetstream: %w", event.ID, err)
	}
	if ack == nil || ack.Stream != p.stream {
		return fmt.Errorf("publish outbox event %q received an invalid stream acknowledgement", event.ID)
	}

	return nil
}

func validateStreamName(stream string) error {
	if stream == "" || len(stream) > 255 {
		return fmt.Errorf("jetstream stream name must contain 1 to 255 characters")
	}
	if strings.ContainsAny(stream, ".*>/\\") || strings.IndexFunc(stream, invalidNATSCharacter) >= 0 {
		return fmt.Errorf("jetstream stream name contains a reserved character")
	}

	return nil
}

func validateSubject(subject string) error {
	if subject == "" || len(subject) > 255 {
		return fmt.Errorf("jetstream subject must contain 1 to 255 characters")
	}
	if strings.IndexFunc(subject, unicode.IsControl) >= 0 {
		return fmt.Errorf("jetstream subject contains a control character")
	}
	for _, token := range strings.Split(subject, ".") {
		if token == "" || strings.ContainsAny(token, "*>\r\n\t ") {
			return fmt.Errorf("jetstream subject must be exact and contain non-empty tokens")
		}
	}

	return nil
}

func invalidNATSCharacter(value rune) bool {
	return unicode.IsSpace(value) || unicode.IsControl(value)
}
