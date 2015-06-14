// Package idm manages resevation/release of numerical ids from a configured set of contiguos ids
package idm

import (
	"fmt"

	"github.com/docker/libnetwork/rleseq"
)

// Idm manages the reservation/release of numerical ids from a contiguos set
type Idm struct {
	start  int
	end    int
	handle *rleseq.Handle
}

// New returns an instance of id manager for a set of [start-end] numerical ids
func New(id string, start, end int) (*Idm, error) {
	if id == "" {
		return nil, fmt.Errorf("Invalid id")
	}
	if end-start <= 0 {
		return nil, fmt.Errorf("Invalid set range: [%d, %d]", start, end)
	}
	return &Idm{start: start, end: end, handle: rleseq.NewHandle(id, uint32(1+end-start))}, nil
}

// GetID returns the first available id in the set
func (i *Idm) GetID() (int, error) {
	if i.handle == nil {
		return 0, fmt.Errorf("ID set is not initialized")
	}

	bytePos, bitPos, err := i.handle.GetFirstAvailable()
	if err != nil {
		return 0, fmt.Errorf("no available ids")
	}
	id := i.start + bitPos + bytePos*8

	// for sets which length is non multiple of 32 this check is needed
	if i.end < id {
		return 0, fmt.Errorf("no available ids")
	}

	i.handle.PushReservation(bytePos, bitPos, false)

	return id, nil
}

// GetSpecificID tries to reserve the specified id
func (i *Idm) GetSpecificID(id int) error {
	if i.handle == nil {
		return fmt.Errorf("ID set is not initialized")
	}

	if id < i.start || id > i.end {
		return fmt.Errorf("Requested id does not belong to the set")
	}

	if bytePos, bitPos, err := i.handle.CheckIfAvailable(id - i.start); err == nil {
		i.handle.PushReservation(bytePos, bitPos, false)
		return nil
	}

	return fmt.Errorf("requested id is not available")
}

// Release releases the specified id
func (i *Idm) Release(id int) {
	ordinal := id - i.start
	i.handle.PushReservation(ordinal/8, ordinal%8, true)
}
