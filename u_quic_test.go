package tls

import (
	"context"
	"testing"
)

func TestUQUICConnCloseThenNextEventNoPanic(t *testing.T) {
	q := UQUICClient(&QUICConfig{
		TLSConfig: &Config{
			ServerName:         "example.com",
			MinVersion:         VersionTLS13,
			InsecureSkipVerify: true,
		},
	}, HelloChrome_Auto)
	q.SetTransportParameters(nil)
	if err := q.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	sawWrite := false
	for range 16 {
		ev := q.NextEvent()
		if ev.Kind == QUICWriteData && len(ev.Data) > 0 {
			sawWrite = true
			break
		}
		if ev.Kind == QUICNoEvent {
			break
		}
	}
	if !sawWrite {
		t.Fatal("expected at least one QUICWriteData event before Close")
	}

	_ = q.Close()

	ev := q.NextEvent()
	if ev.Kind != QUICErrorEvent {
		t.Fatalf("expected QUICErrorEvent after Close, got %v", ev.Kind)
	}
	if ev2 := q.NextEvent(); ev2.Kind != QUICNoEvent {
		t.Fatalf("expected QUICNoEvent after error returned, got %v", ev2.Kind)
	}
}
