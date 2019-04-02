package por

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/klauspost/reedsolomon"
)

// EncodedDataset contains the shards of a dataset and the associated hash for each
// shard.
type EncodedDataset struct {
	shards          [][]byte
	hashes          [][]byte
	ordering        []int
	numDataShards   int
	numParityShards int
}

// CreateErasureCoding creates a maximum distance separable code for a dataset
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

	hashes := make([][]byte, numDataShards+numParityShards)
	ordering := make([]int, numDataShards+numParityShards)

	for i, shard := range shards {
		hashValue := sha256.Sum256(shard)
		hashes[i] = hashValue[:]
		ordering[i] = i
	}

	result := &EncodedDataset{shards, hashes, ordering, numDataShards, numParityShards}

	return result, nil
}

// SelectSegments selects the specified subset of shards from a larger dataset
// and returns that subset as a new EncodedDataset. An error is returned if the
// subset is invalid for the dataset, or if the hashes of the shards of the
// dataset are invalid.
func SelectSegments(dataset *EncodedDataset, subset []int) (*EncodedDataset, error) {
	if len(subset) > len(dataset.shards) {
		return nil, fmt.Errorf("cannot select subset of size %v from set of %v shards",
			len(subset), len(dataset.shards))
	}
	subShards := make([][]byte, len(subset))
	subHashes := make([][]byte, len(subset))
	subOrdering := make([]int, len(subset))

	for i, index := range subset {
		if index >= len(dataset.shards) {
			return nil, fmt.Errorf("cannot select index %v from set of %v shards",
				index, len(dataset.shards))
		}
		subShards[i] = make([]byte, len(dataset.shards[index]))
		copy(subShards[i], dataset.shards[index])
		subHashes[i] = make([]byte, len(dataset.hashes[index]))
		shardHash := sha256.Sum256(subShards[i])
		if !bytes.Equal(shardHash[:], dataset.hashes[index]) {
			return nil, fmt.Errorf("hash of shard %v does not match dataset", index)
		}
		copy(subHashes[i], dataset.hashes[index])
		subOrdering[i] = dataset.ordering[index]
	}

	return &EncodedDataset{subShards, subHashes, subOrdering,
		dataset.numDataShards, dataset.numParityShards}, nil
}

// ReconstructDataFromSegments takes in a slice of EncodedDatasets and restores
// them into the original data. Note that the datasets must contain at least f
// segments of the original data in the correct order, or else an error is
// thrown. An error is also thrown if a hash does not verify for a given
// segment.
func ReconstructDataFromSegments(datasets []*EncodedDataset) ([][]byte, error) {
	return nil, nil
}
