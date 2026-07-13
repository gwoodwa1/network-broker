package sanitise

import "testing"

func TestPipelineRedactsControlsAndBoundsOutput(t *testing.T) {
	pipeline := Pipeline{ID: "safe-text", Version: "v1", Redactions: map[string]string{"hunter2": "[REDACTED]"}, MaximumBytes: 32}
	output, manifest, err := pipeline.Transform([]byte("state=up\x00 password=hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != "state=up password=[REDACTED]" || len(manifest.RedactionsApplied) != 1 {
		t.Fatalf("unexpected sanitised output %q and manifest %+v", output, manifest)
	}
}
