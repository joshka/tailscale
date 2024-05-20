package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
)

var (
	flagDERPMap  = flag.String("derp-map", "https://login.tailscale.com/derpmap/default", "URL to DERP map")
	flagCSV      = flag.String("csv", "", "output csv filename")
	flagInterval = flag.Duration("interval", time.Minute, "interval to probe at in time.ParseDuration() format")
)

func getDERPMap(ctx context.Context, url string) (*tailcfg.DERPMap, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	dm := tailcfg.DERPMap{}
	err = json.NewDecoder(resp.Body).Decode(&dm)
	if err != nil {
		return nil, nil
	}
	return &dm, nil
}

type timestampSource string

const (
	timestampSourceUserspace timestampSource = "userspace"
	timestampSourceKernel    timestampSource = "kernel"
)

type result struct {
	at              time.Time
	hostname        string
	address         string
	timestampSource timestampSource
	rtt             time.Duration
}

func measureRTT(conn *net.UDPConn, dst *net.UDPAddr, req []byte) (resp []byte, rtt time.Duration, err error) {
	err = conn.SetReadDeadline(time.Now().Add(time.Second * 2))
	if err != nil {
		return nil, 0, fmt.Errorf("error setting read deadline: %w", err)
	}
	txAt := time.Now()
	_, err = conn.WriteToUDP(req, dst)
	if err != nil {
		return nil, 0, fmt.Errorf("error writing to udp socket: %w", err)
	}
	b := make([]byte, 1460)
	n, err := conn.Read(b)
	rxAt := time.Now()
	if err != nil {
		return nil, 0, fmt.Errorf("error reading from udp socket: %w", err)
	}
	return b[:n], rxAt.Sub(txAt), nil
}

func isTemporaryErr(err error) bool {
	if err, ok := err.(interface{ Temporary() bool }); ok {
		return err.Temporary()
	}
	return false
}

func probe(hostName string, addr netip.Addr, source timestampSource, interval time.Duration, resultsCh chan<- result, errCh chan<- error, doneCh <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(1)
	defer ticker.Stop()
	first := true

	var (
		sconn io.Closer
		conn  *net.UDPConn
		err   error
	)
	if source == timestampSourceKernel {
		sconn, err = getConnKernelTimestamp()
		if err != nil {
			errCh <- fmt.Errorf("error opening udp socket: %v", err)
			return
		}
		defer sconn.Close()
	} else {
		conn, err = net.ListenUDP("udp", &net.UDPAddr{})
		if err != nil {
			errCh <- fmt.Errorf("error opening udp socket: %v", err)
			return
		}
		defer conn.Close()
	}

	ua := &net.UDPAddr{
		IP:   net.IP(addr.AsSlice()),
		Port: 3478,
	}

	for {
		select {
		case <-doneCh:
			return
		case <-ticker.C:
			if first {
				first = false
				ticker.Reset(interval)
			}
			var (
				resp []byte
				rtt  time.Duration
				err  error
			)
			txID := stun.NewTxID()
			req := stun.Request(txID)
			at := time.Now()
			if source == timestampSourceKernel {
				resp, rtt, err = measureRTTKernel(sconn, ua, req)
			} else {
				resp, rtt, err = measureRTT(conn, ua, req)
			}
			if err != nil {
				if isTemporaryErr(err) || errors.Is(err, os.ErrDeadlineExceeded) {
					log.Printf("temp error measuring RTT to %s(%s): %v", hostName, addr, err)
					continue
				}
				select {
				case errCh <- err:
					return
				case <-doneCh:
					return
				}
			}
			_, _, err = stun.ParseResponse(resp)
			if err != nil {
				log.Printf("invalid stun response: %v", err)
				continue
			}
			select {
			case resultsCh <- result{
				at:              at,
				hostname:        hostName,
				address:         addr.String(),
				timestampSource: source,
				rtt:             rtt,
			}:
			case <-doneCh:
				return
			}
		}
	}

}

func main() {
	flag.Parse()
	if len(*flagDERPMap) < 1 {
		log.Fatal("derp-map flag is unset")
	}
	if len(*flagCSV) < 1 {
		log.Fatal("csv flag is unset")
	}
	if *flagInterval < time.Second {
		log.Fatal("interval must be >= 1s")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	dm, err := getDERPMap(ctx, *flagDERPMap)
	if err != nil {
		log.Fatalf("failed to get DERP map: %v", err)
	}

	of, err := os.Create(*flagCSV)
	if err != nil {
		log.Fatalf("error opening output file for writing: %v", err)
	}
	defer of.Close()
	writer := csv.NewWriter(of)
	err = writer.Write([]string{"at_unix_sec", "hostname", "address", "timestamp_source", "rtt_ns"})
	if err != nil {
		log.Fatalf("error writing csv header: %v", err)
	}

	wg := sync.WaitGroup{}
	doneCh := make(chan struct{})
	resultsCh := make(chan result)
	errCh := make(chan error)
	for _, region := range dm.Regions {
		for _, node := range region.Nodes {
			v4, err := netip.ParseAddr(node.IPv4)
			if err != nil {
				log.Fatalf("invalid ipv4 addr for node: %v", node.Name)
			}
			v6, err := netip.ParseAddr(node.IPv6)
			if err != nil {
				log.Fatalf("invalid ipv6 addr for node: %v", node.Name)
			}
			wg.Add(2)
			go probe(node.HostName, v4, timestampSourceUserspace, *flagInterval, resultsCh, errCh, doneCh, &wg)
			go probe(node.HostName, v6, timestampSourceUserspace, *flagInterval, resultsCh, errCh, doneCh, &wg)
			// TODO:
			/*if runtime.GOOS == "linux" {
				wg.Add(2)
				go probe(node.HostName, v4, timestampSourceKernel, *flagInterval, resultsCh, errCh, doneCh, &wg)
				go probe(node.HostName, v6, timestampSourceKernel, *flagInterval, resultsCh, errCh, doneCh, &wg)
			}*/
		}
	}

	for {
		select {
		case result := <-resultsCh:
			err := writer.Write([]string{
				fmt.Sprintf("%d", result.at.Unix()),
				result.hostname,
				result.address,
				string(result.timestampSource),
				fmt.Sprintf("%d", result.rtt),
			})
			if err != nil {
				log.Printf("error writing result: %v", err)
				close(doneCh)
				wg.Wait()
				return
			}
			writer.Flush()
			err = writer.Error()
			if err != nil {
				log.Printf("error flushing writer: %v", err)
				close(doneCh)
				wg.Wait()
				return
			}
		case err := <-errCh:
			log.Printf("probe error: %v", err)
			close(doneCh)
			wg.Wait()
			return
		case <-sigCh:
			close(doneCh)
			wg.Wait()
			return
		}
	}
}
