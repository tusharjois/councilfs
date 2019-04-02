package por

import (
	"testing"
)

func TestCreateErasureCoding(t *testing.T) {
	// Setup shards
	dataset := []byte("qwertyuiopasdfghjkl")

	// Test Correct Codings
	encoding, err := CreateErasureCoding(dataset, 4, 4)
	if err != nil {
		t.Error(err)
	} else if len(encoding.shards) != 16 {
		t.Errorf("encoding created but with %v != 4 * 4 segments", len(encoding.shards))
	} else if len(encoding.shards) != len(encoding.hashes) {
		t.Errorf("encoding created but with %v shards != %v hashes",
			len(encoding.shards), len(encoding.hashes))
	} else if len(encoding.shards) != len(encoding.ordering) {
		t.Errorf("encoding created but with %v shards != %v ordering",
			len(encoding.shards), len(encoding.ordering))
	} else {
		// t.Logf("dataset encoded into 4 * 4 = %v segments", len(encoding.shards))
	}

	// Test Incorrect Codings
	_, err = CreateErasureCoding(dataset, -1, 0)
	if err == nil {
		t.Errorf("erasure coding created for invalid number of segments")
	} else {
		// t.Log(err)
	}

	_, err = CreateErasureCoding(dataset, 100, 100)
	if err == nil {
		t.Errorf("erasure coding created for too few number of segments")
	} else {
		// t.Log(err)
	}

	_, err = CreateErasureCoding([]byte(""), 4, 4)
	if err == nil {
		t.Errorf("erasure coding created for empty dataset")
	} else {
		// t.Log(err)
	}
}

func TestSelectSegments(t *testing.T) {
	// Prepare encoding
	dataset := []byte("qwertyuiopasdfghjkl")
	encoding, err := CreateErasureCoding(dataset, 4, 4)
	if err != nil {
		t.Fatal(err)
	}

	// Test correct segments
	subset := []int{0, 2, 4, 6, 8}
	subsetEncoding, err := SelectSegments(encoding, subset)
	if err != nil {
		t.Error(err)
	} else if len(subsetEncoding.shards) != 5 {
		t.Errorf("subset created but with %v != 5 segments", len(subsetEncoding.shards))
	} else if len(subsetEncoding.shards) != len(subsetEncoding.hashes) {
		t.Errorf("subset created but with %v shards != %v hashes",
			len(subsetEncoding.shards), len(subsetEncoding.hashes))
	} else if len(subsetEncoding.shards) != len(subsetEncoding.ordering) {
		t.Errorf("subset created but with %v shards != %v ordering",
			len(subsetEncoding.shards), len(subsetEncoding.ordering))
	} else {
		// t.Logf("subset of length %v created", len(subsetEncoding.shards))
	}

}

func TestReconstructDataFromSegments(t *testing.T) {
	// Testing correct recovery of full dataset
	// Testing correct recovery of segmented dataset
	// Testing incorrect recovery
}
