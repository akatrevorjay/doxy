package utils

import (
	"sync"
)

// MySyncCond Extends the sync.Cond struct to add Kill, and Payload
type MySyncCond struct {
    *sync.Cond
    Kill    bool
    Payload int
}

// Init Add an Init() and set Kill to false (declaritive)
func (m *MySyncCond) Init() {
    m.Kill = false
}

// Broadcast Extend sync.Cond.Broadcast() to allow a payload
func (m *MySyncCond) Broadcast(payload int) {
    // set the new payload before broadcasting
    m.Payload = payload
    // call sync.Cond.Broadcast()
    m.Cond.Broadcast()
}
