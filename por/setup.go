package por

import (
	"crypto/sha256"
	"errors"
	"github.com/klauspost/reedsolomon"
)

// EncodedDataset contains the shards of a dataset and the associated hash for each
// shard.
type EncodedDataset struct {
	shards          [][]byte
	hashes          [][sha256.Size]byte
	ordering        []int
	numDataShards   int
	numParityShards int
}

// CreateErasureCoding create a maximum distance separable code for a dataset
// into n = r * f segments, such that any f segments can reconstruct the
// dataset. The input slice is operated on directly. An error is returned if the
// top slice of data does not have length equal to n, or if n is zero, negative,
// or greater than 256. An error is also returned if the data shards are not of
// equal size.
func CreateErasureCoding(dataset []byte, r int, f int) (*EncodedDataset, error) {
	// TODO: Implement Streaming API for better performance with larger files
	// Math: f = d - s; n = d + s; f + n = f(1+r) = 2d; d = (f * (1+r)) / 2
	numDataShards := (f * (1 + r)) / 2
	if numDataShards <= 0 { // there are not any data shards to process
		return nil, errors.New("invalid number of segments")
	}

	numParityShards := numDataShards - f
	shardLen := len(dataset) / numDataShards
	if shardLen <= 0 { // there's not enough data to have this many shards
		return nil, errors.New("dataset too small to support this many segments")
	}

	shards := make([][]byte, numDataShards)
	toShard := make([]byte, len(dataset))
	copy(toShard, dataset)

	for i := range shards {
		startOffset := (i) * shardLen
		endOffset := (i + 1) * shardLen
		if endOffset < len(toShard) {
			shards[i] = toShard[startOffset:endOffset]
		} else {
			shards[i] = toShard[startOffset:len(toShard)]
		}
	}

	enc, err := reedsolomon.New(numDataShards, numParityShards)
	if err != nil { // if top slice has wrong length
		return nil, err
	}

	for i := 0; i < numParityShards; i++ {
		shards = append(shards, make([]byte, shardLen))
	}

	err = enc.Encode(shards)
	if err != nil { // if slices are not of equal length
		return nil, err
	}

	hashes := make([][sha256.Size]byte, numDataShards+numParityShards)
	ordering := make([]int, numDataShards+numParityShards)

	for i, shard := range shards {
		hashes[i] = sha256.Sum256(shard)
		ordering[i] = i
	}

	result := &EncodedDataset{shards, hashes, ordering, numDataShards, numParityShards}

	return result, nil
}

// SelectSegements selects the specified subset of shards from a larger dataset
// and returns that subset as a new EncodedDataset. An error is returned if the
// subset is invalid for the dataset, or if the hashes of the shards of the
// dataset are invalid.
func SelectSegments(dataset *EncodedDataset, subset []int) (*EncodedDataset, error) {

	return nil, nil
}

// ReconstructDataFromSegements takes in a slice of EncodedDatasets and restores them into the
// original data. Note that the datasets must contain all the shards of the
// original data, or else an error is thrown.
func ReconstructDataFromSegments(datasets []EncodedDataset) ([][]byte, error) {
	return nil, nil
}
