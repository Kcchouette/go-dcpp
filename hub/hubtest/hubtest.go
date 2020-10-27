package hubtest

import (
	"fmt"
	"io"
	"log"
	"sync/atomic"

	"github.com/direct-connect/go-dcpp/hub"
	"github.com/direct-connect/go-dcpp/nmdc"
	"github.com/direct-connect/go-dcpp/nmdc/client"
)

type HubConfig struct {
	hub.Config
}

func NewHub(c HubConfig) *Hub {
	h, err := hub.NewHub(c.Config)
	if err != nil {
		panic(err)
	}
	return &Hub{Hub: h}
}

type Hub struct {
	*hub.Hub

	cn int32
}

type NMDCClientConfig struct {
	Name   string
	Secure bool
}

type NMDCClient struct {
	*client.Conn
}

func (h *Hub) LoginNMDC(conf NMDCClientConfig) (*NMDCClient, error) {
	id := int(atomic.AddInt32(&h.cn, 1))
	if conf.Name == "" {
		conf.Name = fmt.Sprintf("peer_%d", id)
	}
	hc, cc := newPipe(id)
	go func() {
		defer hc.Close()
		err := h.ServeNMDC(hc, &hub.ConnInfo{
			Local:  cc.LocalAddr(),
			Remote: cc.RemoteAddr(),
			Secure: conf.Secure,
		})
		if err != nil && err != io.ErrClosedPipe {
			err = fmt.Errorf("hub(%d): %w", id, err)
			log.Println(err)
		}
	}()

	c, err := nmdc.NewConn(cc)
	if err != nil {
		cc.Close()
		return nil, err
	}

	pc, err := client.HubHandshake(c, &client.Config{
		Name: conf.Name,
	})
	if err != nil {
		c.Close()
		cc.Close()
		err = fmt.Errorf("client(%d): %w", id, err)
		return nil, err
	}
	return &NMDCClient{Conn: pc}, nil
}
