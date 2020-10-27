package hub

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"sort"
	"sync"
	"testing"
	"time"

	nmdcp "github.com/direct-connect/go-dc/nmdc"
	"github.com/direct-connect/go-dcpp/nmdc"
	"github.com/direct-connect/go-dcpp/nmdc/client"

	"github.com/stretchr/testify/require"
)

func init() {
	go http.ListenAndServe(":6060", nil)
}

func newPipe(i int) (net.Conn, net.Conn) {
	hc, cc := net.Pipe()
	localhost := net.ParseIP("127.0.0.1")
	ha := &net.TCPAddr{
		IP:   localhost,
		Port: 411,
	}
	ca := &net.TCPAddr{
		IP:   localhost,
		Port: 1000 + i,
	}
	return addrOverride{
			Conn:   hc,
			local:  ha,
			remote: ca,
		}, addrOverride{
			Conn:   cc,
			local:  ca,
			remote: ha,
		}
}

type addrOverride struct {
	net.Conn
	local, remote net.Addr
}

func (c addrOverride) LocalAddr() net.Addr {
	return c.local
}

func (c addrOverride) RemoteAddr() net.Addr {
	return c.remote
}

func newTestHub(t testing.TB) *TestHub {
	h, err := NewHub(Config{})
	require.NoError(t, err)
	return &TestHub{Hub: h}
}

type TestHub struct {
	*Hub
	wg sync.WaitGroup

	mu  sync.Mutex
	err error
}

func (h *TestHub) SetError(err error) {
	if err == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.err = err
}

func (h *TestHub) NewConnNMDC(i int) net.Conn {
	hc, cc := newPipe(i)
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		defer hc.Close()

		err := h.ServeNMDC(hc, nil)
		if err != nil && err != io.ErrClosedPipe {
			err = fmt.Errorf("hub(%d): %v", i, err)
			log.Println(err)
			h.SetError(err)
			return
		}
	}()
	return cc
}

func (h *TestHub) NewClientNMDC(t testing.TB, i int) *client.Conn {
	conn := h.NewConnNMDC(i)
	c := nmdc.NewConn(conn)
	pc, err := client.HubHandshake(c, &client.Config{
		Name: fmt.Sprintf("peer_%d", i),
	})
	require.NoError(t, err)
	return pc
}

func TestHubEnterNMDC(t *testing.T) {
	h := newTestHub(t)

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		last error
	)
	setError := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		last = err
	}
	const delay = time.Second
	start := time.Now()
	const count = 100
	for i := 0; i < count; i++ {
		i := i
		wg.Add(2)
		hc, cc := newPipe(i)
		go func() {
			defer wg.Done()
			defer hc.Close()

			err := h.ServeNMDC(hc, nil)
			if err != nil && err != io.ErrClosedPipe {
				err = fmt.Errorf("hub(%d): %v", i, err)
				log.Println(err)
				setError(err)
				return
			}
		}()
		go func() {
			defer wg.Done()
			defer cc.Close()

			c := nmdc.NewConn(cc)
			defer c.Close()

			pc, err := client.HubHandshake(c, &client.Config{
				Name: fmt.Sprintf("peer_%d", i),
			})
			if err != nil {
				err = fmt.Errorf("client(%d) handshake: %v", i, err)
				log.Println(err)
				setError(err)
				return
			}
			defer pc.Close()

			err = pc.SendChatMsg(fmt.Sprintf("msg %d", i))
			if err != nil {
				err = fmt.Errorf("client(%d) chat: %v", i, err)
				log.Println(err)
				setError(err)
				return
			}
			time.Sleep(delay)
		}()
	}
	wg.Wait()
	t.Logf("enter in %v", time.Since(start)-delay)
	require.NoError(t, last)
}

func requirePeers(t testing.TB, c *client.Conn, exp ...string) {
	exp = append([]string{}, exp...)
	exp = append(exp, "GoHub")
	var got []string
	for _, p := range c.OnlinePeers() {
		got = append(got, p.Info().Name)
	}
	sort.Strings(got)
	sort.Strings(exp)
	require.Equal(t, exp, got)
}

func TestHubTwoClientsNMDC(t *testing.T) {
	h := newTestHub(t)
	const pause = time.Millisecond * 100

	p1 := h.NewClientNMDC(t, 1)
	defer p1.Close()

	requirePeers(t, p1)

	p2 := h.NewClientNMDC(t, 2)
	defer p2.Close()

	time.Sleep(pause)
	requirePeers(t, p1, "peer_2")
	requirePeers(t, p2, "peer_1")

	var (
		mu   sync.RWMutex
		got  *nmdcp.ChatMessage
		wait = make(chan struct{})
	)

	p1.OnChatMessage(func(m *nmdcp.ChatMessage) error {
		mu.Lock()
		defer mu.Unlock()
		if got != nil {
			return errors.New("message already sent")
		}
		got = m
		close(wait)
		return nil
	})
	p1.OnUnhandled(func(m nmdcp.Message) error {
		log.Printf("unhandled: %T", m)
		return nil
	})

	err := p2.SendChatMsg("test")
	require.NoError(t, err)

	select {
	case <-wait:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	p1.OnChatMessage(nil)
	require.Equal(t, &nmdcp.ChatMessage{
		Name: "peer_2",
		Text: "test",
	}, got)

	err = p1.Close()
	require.NoError(t, err)

	time.Sleep(pause)
	requirePeers(t, p2)
}
