package por

import (
	"github.com/klauspost/reedsolomon"
)

// EncodedDataset contains the shards of a dataset and the associated hash for each
// shard.
type EncodedDataset struct {
	shards          [][]byte
	hashes          []byte
	ordering        []byte
	numDataShards   int
	numParityShards int
}

// CreateErasureCoding create a maximum distance separable code for a dataset
// into n = r * f segments, such that any f segments can reconstruct the
// dataset. The input slice is operated on directly. An error is returned if the
// top slice of data does not have length equal to n, or if n is zero, negative,
// or greater than 256. An error is also returned if the data shards are not of
// equal size.
func CreateErasureCoding(shardedData [][]byte, r int, f int) (*EncodedDataset, error) {
	// TODO: Implement Streaming API for better performance with larger files
	// Math: f = d - s; n = d + s; f + n = f(1+r) = 2d; d = (f * (1+r)) / 2
	numDataShards := (f * (1 + r)) / 2
	numParityShards := numDataShards - f
	enc, err := reedsolomon.New(numDataShards, numParityShards)
	if err != nil { // if top slice has wrong length
		return nil, err
	}

	err = enc.Encode(shardedData)
	if err != nil { // if slices are of equal length
		return nil, err
	}

	return nil, nil
}

// SelectSegements selects the specified subset of shards from a larger dataset
// and returns that subset as a new EncodedDataset. An error is returned if the
// subset is invalid for the dataset, or if the hashes of the shards of the
// dataset are invalid.
func SelectSegements(dataset *EncodedDataset, subset []int) (*EncodedDataset, error) {

	return nil, nil
}
