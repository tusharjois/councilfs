package por

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/klauspost/reedsolomon"
	"math"
)

// EncodedDataset contains the shards of a dataset and the associated hash for each
// shard.
type EncodedDataset struct {
	shards          [][]byte
	hashes          [][]byte
	ordering        []int
	numDataShards   int
	numParityShards int
	originalLen     int
}

// Length returns the number of shards in the EncodedDataset.
func (enc *EncodedDataset) Length() uint {
	return uint(len(enc.shards))
}

func computeTreeRoot(shards [][]byte) []byte {
	calculateTreeRoot := make([][]byte, len(shards))
    var length = len(shards)
    for i := 0; i <= length; i++ {
        hashNode := sha256.Sum256(shards[i])
        calculateTreeRoot[i] = hashNode[:]    
    }
    if length > 1 {
    	j := 0
        for i := 0; i <= length - 1; i+=2 {
        	if i + 1 >= length {
                calculateTreeRoot[j] = calculateTreeRoot[i]
                j += 1
        	} else {
        		combine := append(calculateTreeRoot[i], calculateTreeRoot[i+1]...)
                hashNode := sha256.Sum256(combine)
                calculateTreeRoot[j] = hashNode[:]
                j += 1
        	}
        }
        length = j 
    }
    return calculateTreeRoot[0]
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
	shardLen := int(math.Ceil(float64(len(dataset)) / float64(numDataShards)))
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
			// Pad to make sure we can run a proper erasure coding
			for j := len(toShard); j < endOffset; j++ {
				shards[i] = append(shards[i], 0)
			}
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

	result := &EncodedDataset{shards, hashes, ordering, numDataShards, numParityShards, len(dataset)}

	return result, nil
}

// SelectSegments selects the specified subset of shards from a larger dataset
// and returns that subset as a new EncodedDataset. An error is returned if the
// subset is invalid for the dataset, or if the hashes of the shards of the
// dataset are invalid.
func SelectSegments(encoding *EncodedDataset, subset []int) (*EncodedDataset, error) {
	if len(subset) > len(encoding.shards) {
		return nil, fmt.Errorf("cannot select subset of size %v from set of %v shards",
			len(subset), len(encoding.shards))
	}
	subShards := make([][]byte, len(subset))
	subHashes := make([][]byte, len(subset))
	subOrdering := make([]int, len(subset))

	for i, index := range subset {
		if index >= len(encoding.shards) {
			return nil, fmt.Errorf("cannot select index %v from set of %v shards",
				index, len(encoding.shards))
		}
		subShards[i] = make([]byte, len(encoding.shards[index]))
		copy(subShards[i], encoding.shards[index])
		subHashes[i] = make([]byte, len(encoding.hashes[index]))
		shardHash := sha256.Sum256(subShards[i])
		if !bytes.Equal(shardHash[:], encoding.hashes[index]) {
			return nil, fmt.Errorf("hash of shard %v does not match encoding", index)
		}
		copy(subHashes[i], encoding.hashes[index])
		subOrdering[i] = encoding.ordering[index]
	}

	return &EncodedDataset{subShards, subHashes, subOrdering,
		encoding.numDataShards, encoding.numParityShards, encoding.originalLen}, nil
}

// ReconstructDataFromSegments takes in a slice of EncodedDatasets and restores
// them into the original data. Note that the datasets must contain at least f
// segments of the original data in the correct order, or else an error is
// thrown. An error is also thrown if a hash does not verify for a given
// segment.
func ReconstructDataFromSegments(encodings []*EncodedDataset) ([]byte, error) {
	if len(encodings) == 0 {
		return nil, fmt.Errorf("no encodings passed")
	}
	rShards := make([][]byte, encodings[0].numDataShards+encodings[0].numParityShards)
	orderMap := make(map[int][]byte)
	numDataShards := encodings[0].numDataShards
	numParityShards := encodings[0].numParityShards
	originalLen := encodings[0].originalLen

	for idx, encoding := range encodings {
		if numDataShards != encoding.numDataShards {
			return nil, fmt.Errorf("inconsistent numDataShards %v for dataset %v",
				encoding.numDataShards, idx)
		}
		if numParityShards != encoding.numParityShards {
			return nil, fmt.Errorf("inconsistent numParityShards %v for dataset %v",
				encoding.numParityShards, idx)
		}
		if originalLen != encoding.originalLen {
			return nil, fmt.Errorf("inconsistent originalLen %v for dataset %v",
				encoding.originalLen, idx)
		}

		for i, o := range encoding.ordering {
			if o > (numDataShards + numParityShards) {
				return nil, fmt.Errorf("attempting to index %v into dataset of length %v",
					o, numDataShards+numParityShards)
			}
			shardHash := sha256.Sum256(encoding.shards[i])
			if !bytes.Equal(shardHash[:], encoding.hashes[i]) {
				return nil, fmt.Errorf("hash of shard %v in dataset %v does not match dataset",
					o, idx)
			}
			// TODO: Do more complex conflict resolution than this
			if hash, present := orderMap[o]; present {
				if !bytes.Equal(shardHash[:], hash) {
					return nil, fmt.Errorf("hash of shard %v in dataset %v previously found data different",
						o, idx)
				}
			} else {
				rShards[o] = encoding.shards[i]
				orderMap[o] = shardHash[:]
			}
		}

	}

	enc, err := reedsolomon.New(numDataShards, numParityShards)
	if err != nil {
		return nil, err
	}

	err = enc.ReconstructData(rShards)
	if err != nil {
		return nil, err
	}

	result := bytes.Join(rShards, nil)

	return result[:originalLen], nil
}
