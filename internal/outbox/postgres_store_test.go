package outbox

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBoundedErrorProducesValidBoundedUTF8(t *testing.T) {
	failure := strings.Repeat("é", maximumStoredErrorBytes) + string([]byte{0xff})
	bounded := boundedError(failure)
	if len(bounded) > maximumStoredErrorBytes {
		t.Fatalf("expected at most %d bytes, got %d", maximumStoredErrorBytes, len(bounded))
	}
	if !utf8.ValidString(bounded) {
		t.Fatal("expected valid UTF-8")
	}
}

func TestNewPostgresStoreRejectsNilDatabase(t *testing.T) {
	if _, err := NewPostgresStore(nil); err == nil {
		t.Fatal("expected nil database to fail")
	}
}
