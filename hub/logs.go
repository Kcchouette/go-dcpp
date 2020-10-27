package hub

import "log"

var Debug bool

func (h *Hub) Log(args ...interface{}) {
	log.Println(args...)
}

func (h *Hub) Logf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (h *Hub) Debugf(format string, args ...interface{}) {
	if Debug {
		log.Printf(format, args...)
	}
}

// TODO(dennwc): support op chat

func (h *Hub) OpLog(args ...interface{}) {
	h.Log(args...)
}

func (h *Hub) OpLogf(format string, args ...interface{}) {
	h.Logf(format, args...)
}
