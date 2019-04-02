package por

import (
	"testing"
)

func TestCreateErasureCoding(t *testing.T) {
	// Setup shards
	dataset := []byte("qwertyuiopasdfghjkl")

	// Test Correct Codings
	r := 4
	f := 4
	_, err := CreateErasureCoding(dataset, r, f)
	if err != nil {
		t.Error(err)
	}

	// Test Incorrect Codings
	_, err := CreateErasureCoding(dataset, -1, 0)
	if err == nil {
		t.Errorf("erasure coding created for invalid number of segments")
	}

	_, err := CreateErasureCoding(dataset, 100, 100)
	if err == nil {
		t.Errorf("erasure coding created for too few number of segments")
	}

}
