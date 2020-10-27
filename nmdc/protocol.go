package nmdc

import (
	"errors"
	"fmt"
	"io"

	"github.com/direct-connect/go-dc/nmdc"
)

func (c *Conn) SendClientHandshake(ext ...string) (*nmdc.Lock, error) {
	var lock nmdc.Lock
	err := c.ReadMessageTo(&lock)
	if err == io.EOF {
		return nil, io.ErrUnexpectedEOF
	} else if err != nil {
		return nil, err
	}
	if lock.NoExt {
		// TODO: support legacy protocol, if we care
		return nil, errors.New("legacy protocol is not supported")
	}
	bw, err := c.BeginWrite()
	if err != nil {
		return nil, err
	}
	defer bw.Close()
	err = bw.WriteMsg(&nmdc.Supports{Ext: ext})
	if err != nil {
		return nil, err
	}
	err = bw.WriteMsg(lock.Key())
	if err != nil {
		return nil, err
	}
	err = bw.Flush()
	if err != nil {
		return nil, err
	}
	return &lock, nil
}

func (c *Conn) sendClientInfo(bw *nmdc.BatchWriter, info *nmdc.MyINFO) error {
	err := bw.WriteMsg(&nmdc.Version{Vers: "1,0091"})
	if err != nil {
		return err
	}
	err = bw.WriteMsg(&nmdc.GetNickList{})
	if err != nil {
		return err
	}
	err = bw.WriteMsg(info)
	if err != nil {
		return err
	}
	return nil
}

func (c *Conn) SendClientInfo(info *nmdc.MyINFO) error {
	bw, err := c.BeginWrite()
	if err != nil {
		return err
	}
	defer bw.Close()
	err = c.sendClientInfo(bw, info)
	if err != nil {
		return err
	}
	return bw.Flush()
}

func (c *Conn) SendPingerInfo(info *nmdc.MyINFO) error {
	bw, err := c.BeginWrite()
	if err != nil {
		return err
	}
	defer bw.Close()
	err = c.sendClientInfo(bw, info)
	if err != nil {
		return err
	}
	err = bw.WriteMsg(&nmdc.BotINFO{String: nmdc.String(info.Name)})
	if err != nil {
		return err
	}
	return bw.Flush()
}

func (c *Conn) ReadValidateNick() (*nmdc.ValidateNick, error) {
	var nick nmdc.ValidateNick
	err := c.ReadMessageTo(&nick)
	if err != nil {
		return nil, fmt.Errorf("expected validate: %v", err)
	}
	return &nick, nil
}
