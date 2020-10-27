package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dsnet/compress/bzip2"
	"github.com/spf13/cobra"
	"golang.org/x/text/encoding/htmlindex"

	adcp "github.com/direct-connect/go-dc/adc"
	dc "github.com/direct-connect/go-dcpp"
	"github.com/direct-connect/go-dcpp/adc"
	"github.com/direct-connect/go-dcpp/hublist"
	"github.com/direct-connect/go-dcpp/nmdc"
	"github.com/direct-connect/go-dcpp/version"
)

const Version = version.Vers

func main() {
	if err := Root.Execute(); err != nil {
		os.Exit(1)
	}
}

var Root = &cobra.Command{
	Use: "dcping <command>",
}

type timeoutErr interface {
	Timeout() bool
}

func init() {
	versionCmd := &cobra.Command{
		Use: "version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Version:\t%s\nGo runtime:\t%s\n",
				Version, runtime.Version(),
			)
		},
	}
	Root.AddCommand(versionCmd)

	addrsCmd := &cobra.Command{
		Use:   "addrs hublist.xml.bz",
		Short: "read hub addresses from the file and prints them",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("expected file name")
			}
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()

			list, err := hublist.DecodeBZip2(f)
			if err != nil {
				return err
			}
			log.Println(len(list), "hubs")
			for _, h := range list {
				fmt.Print(h.Address + " ")
			}
			fmt.Println()
			return nil
		},
	}
	Root.AddCommand(addrsCmd)

	probeCmd := &cobra.Command{
		Use:   "probe host[:port] [...]",
		Short: "detects DC protocol used by the host",
	}
	probeDebug := probeCmd.Flags().Bool("debug", false, "print protocol messages to stderr")
	probeTimeout := probeCmd.Flags().DurationP("timeout", "t", time.Second*3, "probe timeout")
	probeCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("expected at least one address")
		}
		cmd.SilenceUsage = true

		rctx := context.Background()
		dc.Debug = *probeDebug

		probeOne := func(addr string) error {
			ctx, cancel := context.WithTimeout(rctx, *probeTimeout)
			defer cancel()

			u, err := dc.Probe(ctx, addr)
			if err != nil {
				log.Println(err)
				fmt.Printf("%s - error\n", addr)
				return err
			}
			fmt.Printf("%s\n", u)
			return nil
		}

		var last error
		for _, addr := range args {
			if err := probeOne(addr); err != nil {
				last = err
			}
		}
		return last
	}
	Root.AddCommand(probeCmd)

	pingCmd := &cobra.Command{
		Use:   "ping [proto://]host[:port] [...]",
		Short: "pings the hub and returns its stats",
	}
	pingOut := pingCmd.Flags().String("out", "json", "output format (json, xml or xml-line)")
	pingUsers := pingCmd.Flags().Bool("users", false, "return user list as well")
	pingDebug := pingCmd.Flags().Bool("debug", false, "print protocol messages to stderr")
	pingPretty := pingCmd.Flags().Bool("pretty", false, "pretty-print an output")
	pingNum := pingCmd.Flags().IntP("num", "n", runtime.NumCPU()*2, "number of parallel pings")
	pingTimeout := pingCmd.Flags().DurationP("timeout", "t", time.Second*5, "ping timeout")
	pingFallbackEnc := pingCmd.Flags().StringP("encoding", "e", "", "fallback encoding (e.g. cp1251)")
	pingName := pingCmd.Flags().String("name", "", "name of the pinger")
	pingShare := pingCmd.Flags().Uint64("share", 0, "declared share size (in bytes)")
	pingShareFiles := pingCmd.Flags().Int("files", 0, "declared share files")
	pingSlots := pingCmd.Flags().Int("slots", 0, "declared slots")
	pingHubs := pingCmd.Flags().Int("hubs", 0, "declared hub count")
	pingOutFile := pingCmd.Flags().StringP("file", "f", "", "output file")
	Root.AddCommand(pingCmd)
	pingCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("expected at least one address")
		}
		if name := *pingFallbackEnc; name != "" {
			enc, err := htmlindex.Get(name)
			if err != nil {
				return errors.New("invalid encoding name in --encoding parameter; try the full name (e.g. cp1251)")
			}
			nmdc.DefaultFallbackEncoding = enc
		}
		cmd.SilenceUsage = true

		var (
			mu    sync.Mutex
			w     io.Writer = os.Stdout
			enc   func(interface{}) error
			flush []func() error
		)
		if fname := *pingOutFile; fname != "" && fname != "-" {
			f, err := os.Create(fname)
			if err != nil {
				return err
			}
			defer f.Close()
			flush = append(flush, f.Close)
			w = f
			base := fname
			if strings.HasSuffix(fname, ".gz") {
				base = fname[:len(fname)-3]
				zw := gzip.NewWriter(f)
				flush = append(flush, zw.Close)
				w = zw
			} else if strings.HasSuffix(fname, ".bz2") {
				base = fname[:len(fname)-4]
				zw, err := bzip2.NewWriter(f, nil)
				if err != nil {
					return err
				}
				flush = append(flush, zw.Close)
				w = zw
			}
			if strings.HasSuffix(base, ".xml") && *pingOut != "xml" && *pingOut != "xml-line" {
				*pingOut = "xml"
			} else if strings.HasSuffix(base, ".json") && *pingOut != "json" {
				*pingOut = "json"
			}
		}
		switch *pingOut {
		case "json", "":
			e := json.NewEncoder(w)
			if *pingPretty {
				e.SetIndent("", "\t")
			}
			enc = e.Encode
		case "xml", "xml-line":
			e := hublist.NewXMLWriter(w)
			if *pingName != "" {
				e.SetHublistName(*pingName)
			}
			if *pingOut == "xml-line" {
				e.Headers(false)
			}
			enc = func(o interface{}) error {
				return e.WriteHub(o.(hublist.Hub))
			}
			flush = append(flush, e.Close)
		default:
			return fmt.Errorf("unsupported format: %q", *pingOut)
		}
		cenc := enc
		enc = func(o interface{}) error {
			mu.Lock()
			defer mu.Unlock()
			return cenc(o)
		}
		nmdc.Debug = *pingDebug
		adc.Debug = *pingDebug
		dc.Debug = *pingDebug

		// preprocess args and read hublist files, if any
		var toPing []hublist.Hub
		for i := 0; i < len(args); i++ {
			addr := args[i]
			if strings.HasSuffix(addr, ".xml.bz2") {
				f, err := os.Open(addr)
				if err != nil {
					return err
				}
				list, err := hublist.DecodeBZip2(f)
				_ = f.Close()
				if err != nil {
					return err
				}
				toPing = append(toPing, list...)
			} else if strings.HasSuffix(addr, ".xml") {
				f, err := os.Open(addr)
				if err != nil {
					return err
				}
				list, err := hublist.Decode(f)
				_ = f.Close()
				if err != nil {
					return err
				}
				toPing = append(toPing, list...)
			} else {
				toPing = append(toPing, hublist.Hub{Address: addr})
			}
		}

		rctx := context.Background()

		conf := dc.PingConfig{
			Name:       *pingName,
			ShareSize:  *pingShare,
			ShareFiles: *pingShareFiles,
			Slots:      *pingSlots,
			Hubs:       *pingHubs,
		}

		pingOne := func(h hublist.Hub) error {
			ctx, cancel := context.WithTimeout(rctx, *pingTimeout)
			defer cancel()

			conf := conf
			if h.Encoding != "" {
				enc, err := htmlindex.Get(h.Encoding)
				if err != nil {
					log.Printf("unsupported encoding: %q: %v", h.Encoding, err)
				} else {
					conf.Encoding = enc
				}
			}

			info, err := dc.Ping(ctx, h.Address, &conf)
			if info != nil && !*pingUsers {
				info.UserList = nil
			}
			if info != nil && info.Enc == "" && h.Encoding != "" {
				info.Enc = h.Encoding
			}
			isOffline := false
			if te, ok := err.(timeoutErr); ok && te.Timeout() {
				isOffline = true
			} else if e, ok := err.(*net.OpError); ok && e.Op == "dial" {
				switch e := e.Err.(type) {
				case *net.DNSError:
					isOffline = true
				case *os.SyscallError:
					if e, ok := e.Err.(syscall.Errno); ok {
						// TODO: windows
						switch e {
						case 0x6f: // connection refused
							isOffline = true
						case 0x71: // no route to host
							isOffline = true
						}
					}
				}
			}
			var errCode int
			if e, ok := err.(adcp.Error); ok {
				errCode = int(e.Sev)*100 + e.Code
			}
			switch *pingOut {
			case "json", "":
				status := ""
				if err != nil {
					status = "error"
					if isOffline {
						status = "offline"
					} else {
						log.Printf("%q: %v", h.Address, err)
					}
				}
				if info == nil {
					_ = enc(struct {
						Addr    []string `json:"addr"`
						Status  string   `json:"status,omitempty"`
						ErrCode int      `json:"errcode,omitempty"`
					}{
						Addr:    []string{h.Address},
						Status:  status,
						ErrCode: errCode,
					})
					return err
				}
				if err := enc(struct {
					dc.HubInfo
					Status  string `json:"status,omitempty"`
					ErrCode int    `json:"errcode,omitempty"`
				}{
					HubInfo: *info,
					Status:  status,
					ErrCode: errCode,
				}); err != nil {
					panic(err)
				}
				return err
			case "xml", "xml-line":
				var out hublist.Hub
				status := "Online"
				if err != nil {
					status = "Error"
					if isOffline {
						status = "Offline"
					} else {
						log.Printf("%q: %v", h.Address, err)
					}
				}
				if info != nil {
					out = hublist.Hub{
						Name:        info.Name,
						Address:     info.Addr[0],
						Description: info.Desc,
						Email:       info.Email,
						Encoding:    info.Enc,
						Icon:        info.Icon,
						Website:     info.Website,
						Users:       info.Users,
						Shared:      hublist.Size(info.Share),
						ErrCode:     errCode,
						KeyPrints:   info.KeyPrints,
					}
					// output encoding in the legacy format
					if strings.HasPrefix(out.Encoding, "windows-") {
						out.Encoding = "cp" + strings.TrimPrefix(out.Encoding, "windows-")
					}
					out.Encoding = strings.ToUpper(out.Encoding)
					if info.Server != nil {
						out.Software = info.Server.Name
					}
					for _, addr2 := range info.Addr[1:] {
						if !strings.HasPrefix(h.Address, addr2) && !strings.HasPrefix(addr2, h.Address) {
							out.Failover = addr2
							break
						}
					}
				}
				if out.Address == "" {
					out.Address = h.Address
				}
				out.Status = status
				if err := enc(out); err != nil {
					panic(err)
				}
				return err
			default:
				panic(fmt.Errorf("unsupported format: %q", *pingOut))
			}
		}

		var wg sync.WaitGroup
		jobs := make(chan hublist.Hub, *pingNum)
		errc := make(chan error, 1)
		for i := 0; i < *pingNum; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for h := range jobs {
					if err := pingOne(h); err != nil {
						select {
						case errc <- fmt.Errorf("%q: %w", h.Address, err):
						default:
						}
					}
				}
			}()
		}

		for _, h := range toPing {
			jobs <- h
		}
		close(jobs)
		wg.Wait()
		for i := len(flush) - 1; i >= 0; i-- {
			if err := flush[i](); err != nil {
				return err
			}
		}
		select {
		case err := <-errc:
			return err
		default:
		}
		return nil
	}
}
