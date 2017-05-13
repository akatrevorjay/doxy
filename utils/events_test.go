package utils

type TestEvent struct {
	myNum int
	ch    chan bool
}

func (t *TestEvent) Type() EventType {
	return 0
}

type TestEventHandler struct {
}

func (t *TestEventHandler) EventLoop(ch chan Event) {
	for event := range ch {
		if test, ok := event.(*TestEvent); ok && test.myNum == 42 {
		event.(*TestEvent).ch <- true
		} else {
			event.(*TestEvent).ch <- false
		}
	}
}

// Main #################################################################################################

func main() {
	ch := make(chan bool)
	eventManager := &EventManager{}

	testHandler := &TestEventHandler{}

	eventManager.AddHandler(0, testHandler)

	go eventManager.FireEvent(&TestEvent{42, ch})

	if !<-ch {
		fmt.Println("Fail.")
	} else {
		fmt.Println("Success!")
	}
}
