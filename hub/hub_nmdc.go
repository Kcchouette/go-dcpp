package hub

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	adcp "github.com/direct-connect/go-dc/adc"
	nmdcp "github.com/direct-connect/go-dc/nmdc"
	"github.com/direct-connect/go-dcpp/internal/safe"
	"github.com/direct-connect/go-dcpp/nmdc"
)

var (
	errConnectionClosed = errors.New("connection closed")
)

const (
	nmdcFakeToken        = "nmdc"
	nmdcMaxPerMin        = 30
	nmdcHandshakeTimeout = time.Second * 5
)

var nmdcMaxPerMinCmd = map[string]uint{
	(&nmdcp.MyINFO{}).Type():           30,
	(&nmdcp.TTHSearchPassive{}).Type(): 15,
	(&nmdcp.TTHSearchActive{}).Type():  15,
	(&nmdcp.Search{}).Type():           15,
	(&nmdcp.SR{}).Type():               150,
	(&nmdcp.ConnectToMe{}).Type():      20,
	(&nmdcp.RevConnectToMe{}).Type():   20,
}

func (h *Hub) ServeNMDC(conn net.Conn, cinfo *ConnInfo) error {
	cntConnNMDC.Add(1)
	cntConnNMDCOpen.Add(1)
	defer cntConnNMDCOpen.Add(-1)

	if cinfo == nil {
		cinfo = &ConnInfo{Local: conn.LocalAddr(), Remote: conn.RemoteAddr()}
	}
	if cinfo.TLSVers != 0 {
		cntConnNMDCS.Add(1)
	}
	if cinfo.ALPN != "" {
		cntConnAlpnNMDC.Add(1)
	}

	h.Debugf("%s: using NMDC", conn.RemoteAddr())

	var opts []nmdcp.ConnOption
	opts = append(opts, h.nmdcOpts...)

	c := nmdc.NewConn(conn, opts...)
	c.OnLineR(func(line []byte) (bool, error) {
		sizeNMDCLinesR.Observe(float64(len(line)))
		if h.sampler.enabled() {
			h.sampler.sample(line)
		}
		return true, nil
	})
	c.OnLineW(func(line []byte) (bool, error) {
		sizeNMDCLinesW.Observe(float64(len(line)))
		return true, nil
	})
	c.OnUnmarshalError(func(line []byte, err error) (bool, error) {
		h.Logf("nmdc: failed to unmarshal:\n%q\n", string(line))
		return true, err
	})
	c.OnRawMessageR(func(cmd, data []byte) (bool, error) {
		cnt, ok := sizeNMDCCommandR[string(cmd)]
		if !ok {
			cnt = sizeNMDCCommandR[cmdUnknown]
		}
		if cnt != nil {
			n := 1
			if len(cmd) != 0 {
				n += 1 + len(cmd)
			}
			if len(data) != 0 {
				n += 1 + len(data)
			}
			cnt.Observe(float64(n))
		}
		return true, nil
	})
	c.OnMessageR(func(m nmdcp.Message) (bool, error) {
		countM(cntNMDCCommandsR, m.Type(), 1)
		return true, nil
	})
	c.OnMessageW(func(m nmdcp.Message) (bool, error) {
		countM(cntNMDCCommandsW, m.Type(), 1)
		return true, nil
	})

	peer, err := h.nmdcHandshake(c, cinfo)
	if err != nil {
		c.Drop()
		return err
	} else if peer == nil {
		return c.Close() // pingers
	}
	defer peer.Close()
	return h.nmdcServePeer(peer)
}

func (h *Hub) nmdcLock(deadline time.Time, w *nmdcp.BatchWriter, c *nmdcp.Conn) (nmdcp.Extensions, string, error) {
	if err := c.SetReadDeadline(deadline); err != nil {
		c.Drop()
		return nil, "", err
	}
	if err := w.SetWriteDeadline(deadline); err != nil {
		w.Drop()
		return nil, "", err
	}
	soft := h.getSoft()
	lock := &nmdcp.Lock{
		Lock: "_godcpp", // TODO: randomize
		PK:   soft.Name + " " + soft.Version,
	}
	err := w.WriteMsgNow(lock)
	if err != nil {
		w.Drop()
		return nil, "", err
	}

	var sup nmdcp.Supports
	err = c.ReadMessageTo(&sup)
	if err != nil {
		return nil, "", fmt.Errorf("expected supports: %v", err)
	}
	for _, ext := range sup.Ext {
		cntNMDCExtensions.WithLabelValues(ext).Add(1)
	}
	var key nmdcp.Key
	err = c.ReadMessageTo(&key)
	if err != nil {
		return nil, "", fmt.Errorf("expected key: %v", err)
	} else if key.Key != lock.Key().Key {
		return nil, "", errors.New("wrong key")
	}
	fea := make(nmdcp.Extensions, len(sup.Ext))
	for _, f := range sup.Ext {
		fea[f] = struct{}{}
	}
	if !fea.Has(nmdcp.ExtNoHello) {
		return nil, "", errors.New("NoHello is not supported")
	} else if !fea.Has(nmdcp.ExtNoGetINFO) {
		return nil, "", errors.New("NoGetINFO is not supported")
	}

	err = w.WriteMsgNow(&nmdcp.Supports{
		Ext: nmdcFeatures.List(),
	})
	if err != nil {
		return nil, "", err
	}

	var nick nmdcp.ValidateNick
	err = c.ReadMessageTo(&nick)
	if err != nil {
		return nil, "", fmt.Errorf("expected validate: %v", err)
	}
	return nmdcFeatures.Intersect(fea), string(nick.Name), nil
}

var nmdcFeatures = nmdcp.Extensions{
	nmdcp.ExtNoHello:     {},
	nmdcp.ExtNoGetINFO:   {},
	nmdcp.ExtBotINFO:     {},
	nmdcp.ExtTTHSearch:   {},
	nmdcp.ExtUserIP2:     {},
	nmdcp.ExtUserCommand: {},
	nmdcp.ExtTTHS:        {},
	nmdcp.ExtBotList:     {},
	nmdcp.ExtZPipe0:      {}, // see nmdc.Conn
}

func (h *Hub) nmdcHandshake(c *nmdc.Conn, cinfo *ConnInfo) (*nmdcPeer, error) {
	defer measure(durNMDCHandshake)()
	deadline := time.Now().Add(nmdcHandshakeTimeout)

	w, err := c.BeginWrite()
	if err != nil {
		c.Drop()
		return nil, err
	}
	defer w.Close()

	fea, nick, err := h.nmdcLock(deadline, w, c.Conn)
	if err != nil {
		_ = c.CloseWithChatError(err)
		return nil, err
	}
	addr, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		err = fmt.Errorf("not a tcp address: %T", c.RemoteAddr())
		_ = c.CloseWithChatError(err)
		return nil, err
	}
	name := string(nick)
	err = h.validateUserName(name)
	if err != nil {
		_ = c.CloseWithChatError(err)
		return nil, err
	}

	// if configured, redirect connections to ADC
	if h.getRedirectNMDCToADC() {
		proto := adcp.SchemaADC + "://"
		// account for currently set TLS redirects
		if cinfo.Secure || h.getRedirectNMDCToTLS() || h.getRedirectADCToTLS() {
			proto = adcp.SchemaADCS + "://"
		}
		return nil, c.CloseWithRedirect(proto + cinfo.Local.String())
	}

	// if configured, redirect insecure connections to NMDCS
	if !cinfo.Secure && h.getRedirectNMDCToTLS() {
		return nil, c.CloseWithRedirect(nmdcp.SchemeNMDCS + "://" + cinfo.Local.String())
	}

	peer := newNMDC(h, cinfo, c, fea, nick, addr.IP)

	if peer.fea.Has(nmdcp.ExtBotINFO) {
		cntPings.Add(1)
		cntPingsNMDC.Add(1)
		// it's a pinger - don't bother binding the nickname
		peer.fea.Set(nmdcp.ExtHubINFO)

		err = h.nmdcAccept(w, peer)
		if err != nil {
			return nil, err
		}
		if err := c.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
		var bot nmdcp.BotINFO
		if err := c.ReadMessageTo(&bot); err != nil {
			return nil, err
		}
		st := h.Stats()
		err = c.CloseWith(&nmdcp.HubINFO{
			Name:     st.Name,
			Desc:     st.Desc,
			Host:     st.DefaultAddr(),
			Soft:     st.Soft,
			Encoding: "UTF-8",
		})
		return nil, err
	}

	// do not lock for writes first
	if !h.nameAvailable(name, nil) {
		_ = c.CloseWith(&nmdcp.ValidateDenide{nmdcp.Name(nick)})
		return nil, errNickTaken
	}

	// ok, now lock for writes and try to bind nick
	// still, no one will see the user yet
	unbind, ok := h.reserveName(name, nil, nil)
	if !ok {
		_ = c.CloseWith(&nmdcp.ValidateDenide{nmdcp.Name(nick)})
		return nil, errNickTaken
	}

	err = h.nmdcAccept(w, peer)
	if err != nil || !peer.Online() {
		unbind()

		str := "connection is closed"
		if err != nil {
			str = err.Error()
		}
		_ = peer.c.CloseWith(&nmdcp.ChatMessage{Text: "handshake failed: " + str})
		return nil, err
	}

	var list []Peer
	// finally accept the user on the hub
	h.acceptPeer(peer, func() {
		// make a snapshot of peers to send info to
		list = h.listPeers()
	}, nil)

	// notify other users about the new one
	h.broadcastUserJoin(peer, list)

	if h.conf.ChatLogJoin != 0 && h.getGlobalChatEnabled() {
		h.globalChat.ReplayChat(peer, h.conf.ChatLogJoin)
	}

	return peer, nil
}

// nmdcAccept takes ownership of the write and will close it.
func (h *Hub) nmdcAccept(w *nmdcp.BatchWriter, peer *nmdcPeer) error {
	defer w.Close()
	deadline := time.Now().Add(nmdcHandshakeTimeout)

	c := peer.c

	err := w.WriteMsgDeadline(deadline, &nmdcp.HubName{
		String: nmdcp.String(h.getName()),
	})
	if err != nil {
		w.Drop()
		return err
	}

	user, rec, err := h.getUser(peer.Name())
	if err != nil {
		w.Drop()
		return err
	}
	if user != nil && rec != nil {
		if ci := peer.ConnInfo(); ci != nil && !ci.Secure {
			_ = c.CloseWithChatError(errConnInsecure)
			return errConnInsecure
		}
		err = w.WriteMsgDeadline(deadline, &nmdcp.GetPass{})
		if err != nil {
			w.Drop()
			return err
		}
		// give the user a minute to enter a password
		err = c.SetReadDeadline(time.Now().Add(time.Minute))
		if err != nil {
			c.Drop()
			return err
		}
		var pass nmdcp.MyPass
		err = c.ReadMessageTo(&pass)
		if err != nil {
			return fmt.Errorf("expected password got: %v", err)
		}
		// reset the deadline
		deadline = time.Now().Add(nmdcHandshakeTimeout)

		ok, err := h.nmdcCheckUserPass(rec, string(pass.String))
		if err != nil {
			return err
		}
		if !ok {
			_ = c.CloseWith(&nmdcp.BadPass{})
			return errWrongPass
		}
		peer.setUser(user)
	} else if h.IsPrivate() {
		return errServerIsPrivate
	}

	err = w.WriteMsgDeadline(deadline, &nmdcp.Hello{
		Name: nmdcp.Name(peer.info.user.Name),
	})
	if err != nil {
		c.Drop()
		return err
	}
	// enable Zlib compression, if enable on the hub and if supported by peer
	if lvl := h.zlibLevel(); lvl != 0 && peer.fea.Has(nmdcp.ExtZPipe0) {
		err = c.ZOn(lvl) // flushes
		if err != nil {
			c.Drop()
			return err
		}
	}

	err = c.SetReadDeadline(deadline)
	if err != nil {
		c.Drop()
		return err
	}
	var vers nmdcp.Version
	err = c.ReadMessageTo(&vers)
	if err != nil {
		c.Drop()
		return err
	} else if vers.Vers != "1,0091" && vers.Vers != "1.0091" && vers.Vers != "1,0098" {
		c.Drop()
		return fmt.Errorf("unexpected version: %q", vers)
	}
	curName := peer.info.user.Name

	// according to spec, we should only wait for GetNickList, but some clients
	// skip it and send MyINFO directly when reconnecting
	m, err := c.ReadMessageToAny(&nmdcp.GetNickList{}, &peer.info.user)
	if err != nil {
		c.Drop()
		return err
	}
	switch m.(type) {
	case *nmdcp.GetNickList:
		err = c.ReadMessageTo(&peer.info.user)
		if err != nil {
			c.Drop()
			return fmt.Errorf("expected user info: %v", err)
		}
	case *nmdcp.MyINFO:
		// already read to peer.user
	default:
		c.Drop()
		return fmt.Errorf("expected user info, got: %T", m)
	}
	cli := peer.info.user.Client
	cntClients.WithLabelValues(cli.Name, cli.Version).Add(1)
	if curName != peer.info.user.Name {
		c.Drop()
		return errors.New("nick mismatch")
	}

	peer.setUserInfo(&peer.info.user)

	err = w.WriteMsg(&nmdcp.HubTopic{
		Text: h.getTopic(),
	})
	if err != nil {
		w.Drop()
		return err
	}
	// free the writer lock so we can start writing async
	err = w.Close()
	w = nil
	if err != nil {
		c.Drop()
		return err
	}
	// send everything else async
	aw, err := peer.BeginWriteAsyncNMDC()
	if err != nil {
		c.Drop()
		return err
	}
	defer aw.Close()

	err = aw.HubChatMsg(Message{Text: h.poweredBy()})
	if err != nil {
		return err
	}
	err = h.sendMOTD(peer)
	if err != nil {
		return err
	}

	if peer.fea.Has(nmdcp.ExtUserCommand) {
		err = h.nmdcSendUserCommand(aw, peer)
		if err != nil {
			return err
		}
	}

	// send user list (except his own info)
	peers := h.Peers()
	err = peer.peersJoin(aw, &PeersJoinEvent{Peers: peers}, true)
	if err != nil {
		return err
	}

	// write his info
	err = peer.peersJoin(aw, &PeersJoinEvent{Peers: []Peer{peer}}, true)
	if err != nil {
		return err
	}
	var ops, bots nmdcp.Names
	if u := peer.User(); u != nil && u.Has(FlagOpIcon) {
		ops = append(ops, peer.Name())
	}
	for _, p := range peers {
		if u := p.User(); u != nil && u.Has(FlagOpIcon) {
			ops = append(ops, p.Name())
		}
		if peer.ext.botlist {
			if info := p.UserInfo(); info.Kind == UserBot || info.Kind == UserHub {
				bots = append(bots, p.Name())
			}
		}
	}

	err = aw.WriteMsg(&nmdcp.OpList{Names: ops})
	if err != nil {
		return err
	}
	if peer.ext.botlist && len(bots) != 0 {
		err = aw.WriteMsg(&nmdcp.BotList{Names: bots})
		if err != nil {
			return err
		}
	}
	if peer.ext.userip2 {
		err = aw.WriteMsg(&nmdcp.UserIP{
			List: []nmdcp.UserAddress{{
				Name: peer.Name(),
				IP:   peer.ip.String(),
			}},
		})
		if err != nil {
			return err
		}
		if peer.User().HasPerm(PermIP) {
			var ips []nmdcp.UserAddress
			for _, p := range peers {
				addr, ok := p.RemoteAddr().(*net.TCPAddr)
				if !ok {
					continue
				}
				ips = append(ips, nmdcp.UserAddress{
					Name: p.Name(),
					IP:   addr.IP.String(),
				})
			}
			if len(ips) != 0 {
				err = aw.WriteMsg(&nmdcp.UserIP{List: ips})
				if err != nil {
					return err
				}
			}
		}
	}
	return aw.Close()
}

func (h *Hub) nmdcCheckUserPass(rec *UserRecord, pass string) (bool, error) {
	if h.db == nil {
		return false, nil
	}
	return rec.Pass == pass, nil
}

func (h *Hub) nmdcServePeer(peer *nmdcPeer) error {
	if !h.callOnJoined(peer) {
		return nil // TODO: any errors?
	}

	if err := peer.c.SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	cnt := make(map[string]uint)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		msg, err := peer.c.ReadMessage()
		if err == io.EOF {
			return nil
		} else if err != nil {
			if !peer.Online() {
				return nil
			}
			return err
		}
		typ := msg.Type()
		if !nmdcp.IsRegistered(typ) {
			countM(cntNMDCCommandsDrop, typ, 1)
			continue
		}
		select {
		case <-ticker.C:
			for k := range cnt {
				cnt[k] = 0
			}
		default:
		}
		n := cnt[typ]
		n++
		cnt[typ] = n

		max := uint(nmdcMaxPerMin)
		if v, ok := nmdcMaxPerMinCmd[typ]; ok {
			max = v
		}
		if n >= max {
			countM(cntNMDCCommandsDrop, typ, 1)
			if n == max {
				h.Log("flood:", peer.Name(), typ, msg)
			}
			// TODO: temp ban?
			continue
		}
		if err = h.nmdcHandle(peer, msg); err != nil {
			countM(cntNMDCCommandsDrop, typ, 1)
			return err
		}
	}
}

func (h *Hub) nmdcHandle(peer *nmdcPeer, msg nmdcp.Message) error {
	typ := msg.Type()
	defer measureM(durNMDCHandle, typ)()

	switch msg := msg.(type) {
	case *nmdcp.ChatMessage:
		if string(msg.Name) != peer.Name() {
			return errors.New("invalid name in the chat message")
		}
		if h.isCommand(peer, msg.Text) {
			return nil
		}
		if !h.getGlobalChatEnabled() {
			return nil
		}
		m := Message{
			Name: string(msg.Name),
			Text: string(msg.Text),
		}
		if m.Text == "/me" {
			m.Me = true
			m.Text = ""
		} else if strings.HasPrefix(m.Text, "/me ") {
			m.Me = true
			m.Text = m.Text[4:]
		}
		h.globalChat.SendChat(peer, m)
		return nil
	case *nmdcp.GetNickList:
		list := h.Peers()
		_ = peer.PeersJoin(&PeersJoinEvent{Peers: list})
		return nil
	case *nmdcp.ConnectToMe:
		targ := h.PeerByName(string(msg.Targ))
		if targ == nil || targ == peer {
			countM(cntNMDCCommandsDrop, typ, 1)
			return nil
		}
		if err := peer.verifyAddr(msg.Address); err != nil {
			return fmt.Errorf("ctm: %v", err)
		}
		if msg.Kind == nmdcp.CTMActive {
			// TODO: token?
			h.connectReq(peer, targ, msg.Address, nmdcFakeToken, msg.Secure)
			return nil
		}
		// NAT traversal
		if msg.Src != "" && msg.Src != peer.Name() {
			return errors.New("invalid name in the connect request")
		}
		p2, ok := targ.(*nmdcPeer)
		if !ok {
			countM(cntNMDCCommandsDrop, typ, 1)
			return nil
		}
		return p2.SendNMDC(msg)
	case *nmdcp.RevConnectToMe:
		if string(msg.From) != peer.Name() {
			return errors.New("invalid name in RevConnectToMe")
		}
		targ := h.PeerByName(string(msg.To))
		if targ == nil || targ == peer {
			countM(cntNMDCCommandsDrop, typ, 1)
			return nil
		}
		h.revConnectReq(peer, targ, nmdcFakeToken, targ.UserInfo().TLS)
		return nil
	case *nmdcp.PrivateMessage:
		if name := peer.Name(); string(msg.From) != name || string(msg.Name) != name {
			return errors.New("invalid name in PrivateMessage")
		}
		to := string(msg.To)
		m := Message{
			Name: string(msg.From),
			Text: string(msg.Text),
		}
		if m.Text == "/me" {
			m.Me = true
			m.Text = ""
		} else if strings.HasPrefix(m.Text, "/me ") {
			m.Me = true
			m.Text = m.Text[4:]
		}
		if strings.HasPrefix(to, "#") {
			// message in a chat room
			r := h.Room(to)
			if r == nil {
				countM(cntNMDCCommandsDrop, typ, 1)
				return nil
			}
			r.SendChat(peer, m)
		} else {
			// private message
			targ := h.PeerByName(to)
			if targ == nil {
				countM(cntNMDCCommandsDrop, typ, 1)
				return nil
			}
			h.privateChat(peer, targ, m)
		}
		return nil
	case *nmdcp.Search:
		if msg.Address != "" {
			if err := peer.verifyAddr(msg.Address); err != nil {
				return fmt.Errorf("search: %v", err)
			}
		} else if msg.User != "" {
			if string(msg.User) != peer.Name() {
				return fmt.Errorf("search: invalid nick: %q", msg.User)
			}
		}
		return h.nmdcHandleSearch(peer, msg)
	case *nmdcp.TTHSearchActive:
		if err := peer.verifyAddr(msg.Address); err != nil {
			return fmt.Errorf("search: %v", err)
		}
		// ignore address and deliver results as passive ones
		return h.nmdcHandleSearchTTH(peer, msg.TTH)
	case *nmdcp.TTHSearchPassive:
		if string(msg.User) != peer.Name() {
			return fmt.Errorf("search: invalid nick: %q", msg.User)
		}
		return h.nmdcHandleSearchTTH(peer, msg.TTH)
	case *nmdcp.SR:
		if string(msg.From) != peer.Name() {
			return fmt.Errorf("search: invalid nick: %q", msg.From)
		}
		to := h.PeerByName(string(msg.To))
		if to == nil {
			countM(cntNMDCCommandsDrop, typ, 1)
			return nil
		}
		h.nmdcHandleResult(peer, to, msg)
		return nil
	case *nmdcp.MyINFO:
		if string(msg.Name) != peer.Name() {
			return fmt.Errorf("myinfo: invalid nick: %q", msg.Name)
		} else if u := peer.Info(); u.Client != msg.Client {
			return errors.New("client masquerade is not allowed")
		}
		peer.SetInfo(msg)
		h.broadcastUserUpdate(peer, nil)
		return nil
	default:
		countM(cntNMDCCommandsDrop, typ, 1)
		// TODO
		data, _ := nmdcp.Marshal(nil, msg)
		h.Logf("%s: nmdc: %s", peer.RemoteAddr(), string(data))
		return nil
	}
}

func (h *Hub) nmdcHandleSearchTTH(peer *nmdcPeer, hash TTH) error {
	s, err := peer.newSearch()
	if err != nil {
		return err
	}
	h.Search(TTHSearch(hash), s, nil)
	return nil
}

func (h *Hub) nmdcHandleSearch(peer *nmdcPeer, msg *nmdcp.Search) error {
	// ignore some parameters - all searches will be delivered as passive
	if msg.DataType == nmdcp.DataTypeTTH {
		if peer.fea.Has(nmdcp.ExtTTHS) {
			// ignore duplicate Search requests from peers that supports SP
			return nil
		}
		h.nmdcHandleSearchTTH(peer, *msg.TTH)
		return nil
	}
	var name NameSearch
	if p := strings.TrimSpace(msg.Pattern); p != "" {
		name.And = strings.Split(p, " ")
	}
	var req SearchRequest = name
	if msg.DataType == nmdcp.DataTypeFolders {
		req = DirSearch{name}
	} else if msg.DataType != nmdcp.DataTypeAny || msg.SizeRestricted {
		freq := FileSearch{NameSearch: name}
		if msg.SizeRestricted {
			if msg.IsMaxSize {
				freq.MaxSize = msg.Size
			} else {
				freq.MinSize = msg.Size
			}
		}
		switch msg.DataType {
		case nmdcp.DataTypeAudio:
			freq.FileType = FileTypeAudio
		case nmdcp.DataTypeCompressed:
			freq.FileType = FileTypeCompressed
		case nmdcp.DataTypeDocument:
			freq.FileType = FileTypeDocuments
		case nmdcp.DataTypeExecutable:
			freq.FileType = FileTypeExecutable
		case nmdcp.DataTypePicture:
			freq.FileType = FileTypePicture
		case nmdcp.DataTypeVideo:
			freq.FileType = FileTypeVideo
		}
		req = freq
	}
	s, err := peer.newSearch()
	if err != nil {
		return err
	}
	h.Search(req, s, nil)
	return nil
}

func (h *Hub) nmdcHandleResult(peer *nmdcPeer, to Peer, msg *nmdcp.SR) {
	peer.search.RLock()
	cur := peer.search.peers[to]
	peer.search.RUnlock()

	if cur == nil || cur.out == nil {
		// not searching for anything
		return
	}
	atomic.StoreInt64(&cur.last, time.Now().Unix())
	var res SearchResult
	path := strings.Join(msg.Path, "/")
	if msg.IsDir {
		res = Dir{Peer: peer, Path: path}
	} else {
		res = File{Peer: peer, Path: path, Size: msg.Size, TTH: msg.TTH}
	}
	if !cur.req.Match(res) {
		return
	}
	if err := cur.out.SendResult(res); err != nil {
		_ = cur.out.Close()
		// TODO: remove from the map?
	}
}

func (h *Hub) nmdcSendUserCommand(aw *nmdcAsyncWriter, peer *nmdcPeer) error {
	for _, c := range h.ListCommands(peer.User()) {
		cat := nmdcp.ContextHub
		cmd := "<%[mynick]> !" + c.Name
		if c.opt.OnUser {
			cmd += " %[nick]"
			cat = nmdcp.ContextUser
		}
		cmd += "|"
		err := aw.WriteMsg(&nmdcp.UserCommand{
			Typ:     nmdcp.TypeRaw,
			Context: cat,
			Path:    c.Menu,
			Command: cmd,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *Hub) sendNMDCTo(p Peer, m nmdcp.Message) error {
	switch m := m.(type) {
	case *nmdcp.ChatMessage:
		from := h.PeerByName(m.Name)
		if from == nil {
			return fmt.Errorf("cannot find the message author: '%s'", m.Name)
		}
		if np, ok := p.(*nmdcPeer); ok {
			return np.SendNMDC(m)
		}
		msg := Message{Time: time.Now(), Name: m.Name, Text: m.Text}
		_ = p.ChatMsg(nil, from, msg)
		return nil
	default:
		if np, ok := p.(*nmdcPeer); ok {
			return np.SendNMDC(m)
		}
		h.Logf("TODO: Hub.SendNMDC(%T, %T)", p, m)
		return nil
	}
}

func (h *Hub) SendNMDCTo(p Peer, msgs ...nmdcp.Message) error {
	for _, m := range msgs {
		if err := h.sendNMDCTo(p, m); err != nil && err != errConnectionClosed {
			return err
		}
	}
	return nil
}

var (
	_ Peer      = (*nmdcPeer)(nil)
	_ PeerTopic = (*nmdcPeer)(nil)
)

func newNMDC(h *Hub, cinfo *ConnInfo, c *nmdc.Conn, fea nmdcp.Extensions, nick string, ip net.IP) *nmdcPeer {
	if cinfo == nil {
		cinfo = &ConnInfo{Local: c.LocalAddr(), Remote: c.RemoteAddr()}
	}
	peer := &nmdcPeer{
		c: c, ip: ip,
		fea: fea,
	}
	peer.ext.userip2 = fea.Has(nmdcp.ExtUserIP2)
	peer.ext.botlist = fea.Has(nmdcp.ExtBotList)
	peer.ext.tths = fea.Has(nmdcp.ExtTTHS)
	cinfo.Proto = "NMDC"
	h.newBasePeer(&peer.BasePeer, cinfo)
	peer.info.user.Name = nick
	return peer
}

type nmdcPeer struct {
	BasePeer

	c   *nmdc.Conn
	fea nmdcp.Extensions
	ip  net.IP

	info struct {
		share uint64 // atomic
		sync.RWMutex
		user nmdcp.MyINFO
		buf  *bytes.Buffer
		raw  *nmdcp.RawMessage
	}
	ext struct {
		userip2 bool
		botlist bool
		tths    bool
	}

	search struct {
		sync.RWMutex
		peers  map[Peer]*nmdcSearchRun
		sorted []*nmdcSearchRun
	}
}

func (p *nmdcPeer) Searchable() bool {
	return atomic.LoadUint64(&p.info.share) > 0
}

type nmdcSearchRun struct {
	last int64 // sec
	req  SearchRequest
	out  Search
}

func (p *nmdcPeer) SetInfo(u *nmdcp.MyINFO) {
	p.info.Lock()
	defer p.info.Unlock()
	p.setUserInfo(u)
}

func (p *nmdcPeer) setUserInfo(u *nmdcp.MyINFO) {
	if u != &p.info.user {
		p.info.user = *u
	}
	if p.info.buf == nil {
		p.info.buf = bytes.NewBuffer(nil)
	} else {
		p.info.buf.Reset()
	}
	err := u.MarshalNMDC(p.c.Encoding(), p.info.buf)
	if err != nil {
		panic(err)
	}
	p.info.raw = &nmdcp.RawMessage{Typ: u.Type(), Data: p.info.buf.Bytes()}
	atomic.StoreUint64(&p.info.share, u.ShareSize)
}

func (p *nmdcPeer) UserInfo() UserInfo {
	u := p.Info()
	return UserInfo{
		Name:           string(u.Name),
		App:            u.Client,
		HubsNormal:     u.HubsNormal,
		HubsRegistered: u.HubsRegistered,
		HubsOperator:   u.HubsOperator,
		Slots:          u.Slots,
		Email:          u.Email,
		Desc:           u.Desc,
		Share:          u.ShareSize,
		IPv4:           u.Flag.IsSet(nmdcp.FlagIPv4),
		IPv6:           u.Flag.IsSet(nmdcp.FlagIPv6),
		TLS:            u.Flag.IsSet(nmdcp.FlagTLS),
	}
}

func (p *nmdcPeer) Name() string {
	p.info.RLock()
	name := p.info.user.Name
	p.info.RUnlock()
	return string(name)
}

func (p *nmdcPeer) rawInfo() (*nmdcp.RawMessage, *nmdcp.Encoding) {
	p.info.RLock()
	data := p.info.raw
	p.info.RUnlock()
	return data, p.c.Encoding()
}

func (p *nmdcPeer) Info() nmdcp.MyINFO {
	p.info.RLock()
	u := p.info.user
	p.info.RUnlock()
	return u
}

func (p *nmdcPeer) closeOn(list []Peer) error {
	return p.closeWith(p,
		p.c.Close,
		func() error {
			p.hub.leave(p, p.sid, list)
			p.dropSearches()
			return nil
		},
	)
}

func (p *nmdcPeer) Close() error {
	return p.closeOn(nil)
}

type nmdcAsyncWriter struct {
	p *nmdcPeer
	*nmdcp.AsyncWriter
}

func (w *nmdcAsyncWriter) HubChatMsg(m Message) error {
	if !w.p.Online() {
		return errConnectionClosed
	}
	if m.Name == "" {
		m.Name = w.p.hub.getName()
	}
	return w.WriteMsg(&nmdcp.ChatMessage{Name: m.Name, Me: m.Me, Text: m.Text})
}

func (p *nmdcPeer) BeginWriteAsyncNMDC() (*nmdcAsyncWriter, error) {
	if !p.Online() {
		return nil, errConnectionClosed
	}
	aw, err := p.c.BeginWriteAsync()
	if err != nil {
		return nil, err
	}
	return &nmdcAsyncWriter{p: p, AsyncWriter: aw}, nil
}

func (p *nmdcPeer) SendNMDC(m ...nmdcp.Message) error {
	aw, err := p.BeginWriteAsyncNMDC()
	if err != nil {
		return err
	}
	defer aw.Close()
	err = aw.WriteMsg(m...)
	if err != nil {
		return err
	}
	return aw.Close()
}

func (p *nmdcPeer) verifyAddr(addr string) error {
	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address: %q", addr)
	}
	_, err = strconv.ParseUint(port, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port: %q", addr)
	}
	if ip != p.ip.String() {
		return fmt.Errorf("invalid ip: %q vs %q", ip, p.ip.String())
	}
	return nil
}

func (p *nmdcPeer) Topic(topic string) error {
	return p.SendNMDC(&nmdcp.HubTopic{Text: topic})
}

func (p *nmdcPeer) PeersJoin(e *PeersJoinEvent) error {
	aw, err := p.BeginWriteAsyncNMDC()
	if err != nil {
		return err
	}
	defer aw.Close()
	if err = p.peersJoin(aw, e, false); err != nil {
		return err
	}
	return aw.Flush()
}

func (p *nmdcPeer) PeersUpdate(e *PeersUpdateEvent) error {
	// same as join
	return p.PeersJoin((*PeersJoinEvent)(e))
}

func NMDCUserInfo(p Peer) nmdcp.MyINFO {
	if np, ok := p.(*nmdcPeer); ok {
		return np.Info()
	}
	u := p.UserInfo()
	return u.toNMDC()
}

func (u UserInfo) toNMDC() nmdcp.MyINFO {
	flag := nmdcp.FlagStatusNormal
	if u.IPv4 {
		flag |= nmdcp.FlagIPv4
	}
	if u.IPv6 {
		flag |= nmdcp.FlagIPv6
	}
	if u.TLS {
		flag |= nmdcp.FlagTLS
	}
	conn := "100"                 // TODO
	mode := nmdcp.UserModePassive // TODO
	if u.Kind == UserBot || u.Kind == UserHub {
		conn = "" // empty conn indicates a bot
	}
	return nmdcp.MyINFO{
		Name:           u.Name,
		Client:         u.App,
		HubsNormal:     u.HubsNormal,
		HubsRegistered: u.HubsRegistered,
		HubsOperator:   u.HubsOperator,
		Slots:          u.Slots,
		Email:          u.Email,
		Desc:           u.Desc,
		ShareSize:      u.Share,
		Flag:           flag,
		Conn:           conn,
		Mode:           mode,
	}
}

func nmdcPeersJoinCmds(enc *nmdcp.Encoding, peers []Peer) []nmdcp.Message {
	cmds := make([]nmdcp.Message, 0, len(peers))
	for _, p2 := range peers {
		if p2n, ok := p2.(*nmdcPeer); ok {
			raw, enc2 := p2n.rawInfo()
			if (enc == nil && enc2 == nil) || (enc != nil && enc2 != nil) {
				// same encoding
				cmds = append(cmds, raw)
			} else {
				myinfo := p2n.Info()
				cmds = append(cmds, &myinfo)
			}
		} else {
			myinfo := p2.UserInfo().toNMDC()
			cmds = append(cmds, &myinfo)
		}
	}
	return cmds
}

func nmdcPeersOpCmds(peers []Peer) []nmdcp.Message {
	var ops nmdcp.Names
	for _, p2 := range peers {
		if p2.User().Has(FlagOpIcon) {
			// operator flag is sent as a separate command
			ops = append(ops, p2.Name())
		}
	}
	if len(ops) == 0 {
		return nil
	}
	return []nmdcp.Message{&nmdcp.OpList{Names: ops}}
}

func nmdcPeersBotsCmds(peers []Peer) []nmdcp.Message {
	var bots nmdcp.Names
	for _, p2 := range peers {
		if info := p2.UserInfo(); info.Kind == UserBot || info.Kind == UserHub {
			bots = append(bots, p2.Name())
		}
	}
	if len(bots) == 0 {
		return nil
	}
	return []nmdcp.Message{&nmdcp.BotList{Names: bots}}
}

func nmdcPeersIPCmds(peers []Peer) []nmdcp.Message {
	var ips []nmdcp.UserAddress
	for _, p2 := range peers {
		if addr, ok := p2.RemoteAddr().(*net.TCPAddr); ok {
			ips = append(ips, nmdcp.UserAddress{
				Name: p2.Name(),
				IP:   addr.IP.String(),
			})
		}
	}
	if len(ips) == 0 {
		return nil
	}
	return []nmdcp.Message{&nmdcp.UserIP{List: ips}}
}

func (p *nmdcPeer) peersJoin(aw *nmdcAsyncWriter, e *PeersJoinEvent, initial bool) error {
	ec := p.c.Encoding()

	if e.nmdcInfos == nil {
		e.nmdcInfos = &nmdcp.Buffer{}
		m := nmdcPeersJoinCmds(ec, e.Peers)
		if err := e.nmdcInfos.WriteMessage(m...); err != nil {
			return err
		}
	}
	line, err := e.nmdcInfos.BytesFor(ec)
	if err != nil {
		return err
	}
	if err := aw.WriteLine(line); err != nil {
		return err
	}
	if initial {
		// caller will send ips, ops and bots manually
		return nil
	}

	// operators flag is a separate command
	if e.nmdcOps == nil {
		e.nmdcOps = &nmdcp.Buffer{}
		m := nmdcPeersOpCmds(e.Peers)
		if err := e.nmdcOps.WriteMessage(m...); err != nil {
			return err
		}
	}
	line, err = e.nmdcOps.BytesFor(ec)
	if err != nil {
		return err
	}
	if err := aw.WriteLine(line); err != nil {
		return err
	}

	// if supported, send a bot list
	if p.ext.botlist {
		if e.nmdcBots == nil {
			e.nmdcBots = &nmdcp.Buffer{}
			m := nmdcPeersBotsCmds(e.Peers)
			if err := e.nmdcBots.WriteMessage(m...); err != nil {
				return err
			}
		}
		line, err = e.nmdcBots.BytesFor(ec)
		if err != nil {
			return err
		}
		if err := aw.WriteLine(line); err != nil {
			return err
		}
	}

	// send IPs if the user is an operator
	if p.ext.userip2 && p.User().HasPerm(PermIP) {
		if e.nmdcIPs == nil {
			e.nmdcIPs = &nmdcp.Buffer{}
			m := nmdcPeersIPCmds(e.Peers)
			if err := e.nmdcIPs.WriteMessage(m...); err != nil {
				return err
			}
		}
		line, err := e.nmdcIPs.BytesFor(ec)
		if err != nil {
			return err
		}
		if err := aw.WriteLine(line); err != nil {
			return err
		}
	}
	return nil
}

func nmdcPeersLeaveCmds(peers []Peer) []nmdcp.Message {
	cmds := make([]nmdcp.Message, 0, len(peers))
	for _, p2 := range peers {
		cmds = append(cmds, &nmdcp.Quit{
			Name: nmdcp.Name(p2.Name()),
		})
	}
	return cmds
}

func (p *nmdcPeer) PeersLeave(e *PeersLeaveEvent) error {
	if e == nil || len(e.Peers) == 0 {
		return nil
	} else if !p.Online() {
		return errConnectionClosed
	}
	ec := p.c.Encoding()
	if e.nmdcQuit == nil {
		e.nmdcQuit = &nmdcp.Buffer{}
		m := nmdcPeersLeaveCmds(e.Peers)
		if err := e.nmdcQuit.WriteMessage(m...); err != nil {
			return err
		}
	}
	line, err := e.nmdcQuit.BytesFor(ec)
	if err != nil {
		return err
	}
	return p.c.WriteLineAsync(line)
}

func (p *nmdcPeer) JoinRoom(room *Room) error {
	if !p.Online() {
		return errConnectionClosed
	}
	rname := room.Name()
	if rname == "" {
		return nil
	}
	return p.SendNMDC(
		&nmdcp.MyINFO{
			Name:       rname,
			HubsNormal: room.Users(), // TODO: update
			Client:     p.hub.getSoft(),
			Mode:       nmdcp.UserModeActive,
			Flag:       nmdcp.FlagStatusServer,
			Slots:      1,
			Conn:       nmdcp.ConnSpeedModem, // "modem" icon
		},
		&nmdcp.OpList{
			Names: nmdcp.Names{rname},
		},
		&nmdcp.PrivateMessage{
			From: rname, Name: rname,
			To:   p.Name(),
			Text: "/me joined",
		},
	)
}

func (p *nmdcPeer) LeaveRoom(room *Room) error {
	if !p.Online() {
		return errConnectionClosed
	}
	rname := room.Name()
	if rname == "" {
		return nil
	}
	return p.SendNMDC(
		&nmdcp.PrivateMessage{
			From: rname, Name: rname,
			To:   p.Name(),
			Text: "/me parted",
		},
		&nmdcp.Quit{
			Name: nmdcp.Name(rname),
		},
	)
}

func ToNMDCChatMsg(from Peer, msg Message) *nmdcp.ChatMessage {
	if msg.Me && !strings.HasPrefix(msg.Text, "/me") {
		msg.Text = "/me " + msg.Text
	}
	if msg.Name == "" {
		msg.Name = from.Name()
	}
	return &nmdcp.ChatMessage{
		Name: msg.Name,
		Text: msg.Text,
	}
}

func (p *nmdcPeer) ChatMsg(room *Room, from Peer, msg Message) error {
	if !p.Online() {
		return errConnectionClosed
	}
	m := ToNMDCChatMsg(from, msg)
	if room == nil || room.Name() == "" {
		return p.SendNMDC(m)
	}
	if from == p {
		return nil // no echo
	}
	return p.SendNMDC(&nmdcp.PrivateMessage{
		From: room.Name(),
		To:   p.Name(),
		Name: m.Name,
		Text: m.Text,
	})
}

func (p *nmdcPeer) PrivateMsg(from Peer, msg Message) error {
	if !p.Online() {
		return errConnectionClosed
	}
	if msg.Me && !strings.HasPrefix(msg.Text, "/me") {
		msg.Text = "/me " + msg.Text
	}
	fname := msg.Name
	return p.SendNMDC(&nmdcp.PrivateMessage{
		From: fname, Name: fname,
		To:   p.Name(),
		Text: msg.Text,
	})
}

func (p *nmdcPeer) HubChatMsg(m Message) error {
	aw, err := p.BeginWriteAsyncNMDC()
	if err != nil {
		return err
	}
	defer aw.Close()
	err = aw.HubChatMsg(m)
	if err != nil {
		return err
	}
	return aw.Close()
}

func (p *nmdcPeer) ConnectTo(peer Peer, addr string, token string, secure bool) error {
	if !p.Online() {
		return errConnectionClosed
	}
	// TODO: save token somewhere?
	return p.SendNMDC(&nmdcp.ConnectToMe{
		Targ:    peer.Name(),
		Address: addr,
		Secure:  secure,
	})
}

func (p *nmdcPeer) RevConnectTo(peer Peer, token string, secure bool) error {
	if !p.Online() {
		return errConnectionClosed
	}
	// TODO: save token somewhere?
	return p.SendNMDC(&nmdcp.RevConnectToMe{
		From: peer.Name(),
		To:   p.Name(),
	})
}

func (p *nmdcPeer) newSearch() (Search, error) {
	aw, err := p.c.BeginWriteAsync()
	if err != nil {
		return nil, err
	}
	return &nmdcSearch{p: p, aw: aw}, nil
}

// nmdcSearch is bound to a single search request.
type nmdcSearch struct {
	p      *nmdcPeer
	aw     *nmdcp.AsyncWriter
	closed safe.Bool

	// buffers for marshaling the request in different encodings.
	bufSP     *nmdcp.Buffer
	bufSearch *nmdcp.Buffer
}

func (s *nmdcSearch) Peer() Peer {
	return s.p
}

func (s *nmdcSearch) SendResult(r SearchResult) error {
	if !s.p.Online() || s.closed.Get() {
		return errConnectionClosed
	}
	h := s.p.hub
	// TODO: additional filtering?
	sr := &nmdcp.SR{
		From:      r.From().Name(),
		FreeSlots: 3, TotalSlots: 3, // TODO
		HubName:    h.Stats().Name,
		HubAddress: s.p.LocalAddr().String(),
	}
	switch r := r.(type) {
	case File:
		sr.Path = strings.Split(r.Path, "/")
		sr.Size = r.Size
		if r.TTH != nil {
			sr.HubName = ""
			sr.TTH = r.TTH
		}
	case Dir:
		sr.Path = strings.Split(r.Path, "/")
		sr.IsDir = true
	default:
		return nil // ignore
	}
	return s.aw.WriteMsg(sr)
}

func (s *nmdcSearch) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		return nil
	}
	// flush results
	return s.aw.Close()
}

func (p *nmdcPeer) gcSearches() {
	now := time.Now().Unix()
	last := -1
	for i, s := range p.search.sorted {
		if now-atomic.LoadInt64(&s.last) > int64(searchTimeout/time.Second) {
			last = i
		} else {
			break
		}
	}
	if last < 1000 && last < len(p.search.sorted)/40 {
		return
	}
	for _, s := range p.search.sorted[:last] {
		_ = s.out.Close()
		delete(p.search.peers, s.out.Peer())
	}
	p.search.sorted = p.search.sorted[last:]
}

func (p *nmdcPeer) dropSearches() {
	p.search.Lock()
	p.search.peers = nil
	p.search.Unlock()
}

func (p *nmdcPeer) setActiveSearch(out Search, req SearchRequest) {
	p2 := out.Peer()
	p.search.Lock()
	defer p.search.Unlock()
	cur := p.search.peers[p2]
	if cur != nil && cur.out != nil {
		_ = cur.out.Close()
	}
	if p.search.peers == nil {
		p.search.peers = make(map[Peer]*nmdcSearchRun)
	} else {
		p.gcSearches()
	}
	s := &nmdcSearchRun{out: out, req: req}
	atomic.StoreInt64(&s.last, time.Now().Unix())
	p.search.peers[p2] = s
	p.search.sorted = append(p.search.sorted, s)
}

func (p *nmdcPeer) searchCmdTTH(from Peer, req TTH) nmdcp.Message {
	if p.ext.tths {
		return &nmdcp.TTHSearchPassive{
			User: from.Name(),
			TTH:  TTH(req),
		}
	}
	return &nmdcp.Search{
		User:     from.Name(),
		DataType: nmdcp.DataTypeTTH, TTH: (*TTH)(&req),
	}
}

func (p *nmdcPeer) searchCmdOther(from Peer, req SearchRequest) *nmdcp.Search {
	msg := &nmdcp.Search{
		User:     from.Name(),
		DataType: nmdcp.DataTypeAny,
	}
	var name NameSearch
	switch req := req.(type) {
	case NameSearch:
		name = req
	case DirSearch:
		name = req.NameSearch
		msg.DataType = nmdcp.DataTypeFolders
	case FileSearch:
		name = req.NameSearch
		if req.MaxSize != 0 {
			// prefer max size
			msg.SizeRestricted = true
			msg.IsMaxSize = true
			msg.Size = req.MaxSize
		} else if req.MinSize != 0 {
			msg.SizeRestricted = true
			msg.IsMaxSize = false
			msg.Size = req.MinSize
		}
		switch req.FileType {
		case FileTypeAudio:
			msg.DataType = nmdcp.DataTypeAudio
		case FileTypeCompressed:
			msg.DataType = nmdcp.DataTypeCompressed
		case FileTypeDocuments:
			msg.DataType = nmdcp.DataTypeDocument
		case FileTypeExecutable:
			msg.DataType = nmdcp.DataTypeExecutable
		case FileTypePicture:
			msg.DataType = nmdcp.DataTypePicture
		case FileTypeVideo:
			msg.DataType = nmdcp.DataTypeVideo
		}
	default:
		return nil // ignore
	}
	msg.Pattern += strings.Join(name.And, " ")
	return msg
}

func (p *nmdcPeer) Search(ctx context.Context, req SearchRequest, out Search) error {
	if !p.Online() {
		return errConnectionClosed
	}
	p.setActiveSearch(out, req)
	if req, ok := req.(TTHSearch); ok {
		ns, ok := out.(*nmdcSearch)
		if !ok {
			cmd := p.searchCmdTTH(out.Peer(), TTH(req))
			return p.SendNMDC(cmd)
		}
		enc := ns.p.c.Encoding()
		ptr := &ns.bufSearch
		if p.ext.tths {
			ptr = &ns.bufSP
		}
		buf := *ptr
		if buf == nil {
			// first peer - add search command to the encoding buffer
			buf = &nmdcp.Buffer{}
			*ptr = buf
			m := p.searchCmdTTH(out.Peer(), TTH(req))
			if err := buf.WriteMessage(m); err != nil {
				return err
			}
		}
		line, err := buf.BytesFor(enc)
		if err != nil {
			return err
		}
		return p.c.WriteLineAsync(line)
	}
	ns, ok := out.(*nmdcSearch)
	if !ok {
		msg := p.searchCmdOther(out.Peer(), req)
		return p.SendNMDC(msg)
	}
	enc := ns.p.c.Encoding()
	if ns.bufSearch == nil {
		// first peer - add search command to the encoding buffer
		ns.bufSearch = &nmdcp.Buffer{}
		m := p.searchCmdOther(out.Peer(), req)
		if err := ns.bufSearch.WriteMessage(m); err != nil {
			return err
		}
	}
	line, err := ns.bufSearch.BytesFor(enc)
	if err != nil {
		return err
	}
	return p.c.WriteLineAsync(line)
}

func (p *nmdcPeer) Redirect(addr string) error {
	if !p.Online() {
		return errConnectionClosed
	}
	return p.c.CloseWith(&nmdcp.ForceMove{
		Address: addr,
	})
}
