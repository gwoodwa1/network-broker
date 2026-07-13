package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nats-io/nats.go/jetstream"
)

type jetStreamPublisherStub struct {
	ack     *jetstream.PubAck
	err     error
	subject string
	payload []byte
}

func (s *jetStreamPublisherStub) Publish(_ context.Context, subject string, payload []byte,
	_ ...jetstream.PublishOpt,
) (*jetstream.PubAck, error) {
	s.subject = subject
	s.payload = append([]byte(nil), payload...)

	return s.ack, s.err
}

func TestJetStreamPublisherSendsVersionedEnvelope(t *testing.T) {
	client := &jetStreamPublisherStub{ack: &jetstream.PubAck{Stream: "BROKER_EVENTS", Sequence: 7}}
	publisher, err := NewJetStreamPublisher(client, "BROKER_EVENTS", "network-broker.events")
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Publish(context.Background(), validEvent("event-1")); err != nil {
		t.Fatal(err)
	}
	var envelope eventEnvelope
	if err := json.Unmarshal(client.payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if client.subject != "network-broker.events" || envelope.Schema != envelopeSchema || envelope.ID != "event-1" {
		t.Fatalf("unexpected publication: subject=%q envelope=%+v", client.subject, envelope)
	}
	if string(envelope.Payload) != `{"schema_version":"v1"}` {
		t.Fatalf("unexpected embedded payload: %s", envelope.Payload)
	}
}

func TestJetStreamPublisherFailsClosed(t *testing.T) {
	client := &jetStreamPublisherStub{ack: &jetstream.PubAck{Stream: "WRONG"}}
	publisher, err := NewJetStreamPublisher(client, "BROKER_EVENTS", "network-broker.events")
	if err != nil {
		t.Fatal(err)
	}
	invalid := validEvent("event-1")
	invalid.Payload = []byte(`not-json`)
	if err := publisher.Publish(context.Background(), invalid); err == nil {
		t.Fatal("expected invalid JSON payload to fail")
	}
	if err := publisher.Publish(context.Background(), validEvent("event-1")); err == nil {
		t.Fatal("expected wrong stream acknowledgement to fail")
	}
	client.err = errors.New("unavailable")
	if err := publisher.Publish(context.Background(), validEvent("event-1")); err == nil {
		t.Fatal("expected broker failure to propagate")
	}
}

func TestJetStreamPublisherRejectsUnsafeConfiguration(t *testing.T) {
	client := &jetStreamPublisherStub{}
	for _, subject := range []string{"", "network.*", "network..events", "network events"} {
		if _, err := NewJetStreamPublisher(client, "BROKER_EVENTS", subject); err == nil {
			t.Fatalf("expected subject %q to fail", subject)
		}
	}
	if _, err := NewJetStreamPublisher(client, "BROKER.EVENTS", "network.events"); err == nil {
		t.Fatal("expected unsafe stream name to fail")
	}
}
