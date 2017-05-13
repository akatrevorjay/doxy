package utils

type EventType uint8

var nextEventId EventType

func NextEventId() EventType {
	defer func() { nextEventId++ }()
	return nextEventId
}

type Event interface {
	Type() EventType // Returns the event type for this event
}

type EventHandler interface {
	EventLoop(ch chan Event)
}

type EventManager struct {
	rCounts  []int        // Receiver counts for each event type
	channels []chan Event // Channels for each event type
}

// AddHandler adds an event handler for a particular event type
func (e *EventManager) AddHandler(eventType EventType, handler EventHandler) {
	if int(eventType) >= len(e.rCounts) { // Check if we have enough room
		// Resize the handler tables accordingly
		newRCounts := make([]int, eventType+1)       // Counts
		newRChans := make([]chan Event, eventType+1) // Channels
		copy(newRCounts, e.rCounts)
		copy(newRChans, e.channels)
		e.rCounts = newRCounts
		e.channels = newRChans

		// Create new count and channel
		e.rCounts[eventType] = 1
		e.channels[eventType] = make(chan Event, 1)
	} else {
		e.rCounts[eventType]++
		e.channels[eventType] = make(chan Event, e.rCounts[eventType])
	}

	go handler.EventLoop(e.channels[eventType])
}

// Fire fires an event to all receivers receiving
func (e *EventManager) Fire(event Event) {
	// No handlers for this event type
	if len(e.rCounts) <= int(event.Type()) {
		return
	}

	for i := 0; i < e.rCounts[event.Type()]; i++ {
		e.channels[event.Type()] <- event
	}
}
