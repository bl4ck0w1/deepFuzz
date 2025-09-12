package evasion

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"golang.org/x/net/proxy"
)

type TorTransport struct {
	client *http.Client
	dialer proxy.Dialer
	addr   string
}

func NewTorTransport() *TorTransport {
	tt, _ := NewTorTransportAt("127.0.0.1:9050")
	return tt
}

func NewTorTransportAt(socks5Addr string) (*TorTransport, error) {
	dialer, err := proxy.SOCKS5("tcp", socks5Addr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.Dial(network, address)
		},
		DisableKeepAlives:  false,
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &TorTransport{
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		dialer: dialer,
		addr:   socks5Addr,
	}, nil
}

func (t *TorTransport) Client() *http.Client {
	return t.client
}

func (t *TorTransport) GetWithError(url string) (string, error) {
	resp, err := t.client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (t *TorTransport) Get(url string) string {
	body, err := t.GetWithError(url)
	if err != nil {
		return ""
	}
	return body
}

func (t *TorTransport) ResetIdentity(controlAddr, password string) error {
	conn, err := net.DialTimeout("tcp", controlAddr, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	if password == "" {
		if _, err := fmt.Fprintf(w, "AUTHENTICATE\r\n"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(w, "AUTHENTICATE \"%s\"\r\n", password); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "250") {
		return fmt.Errorf("tor control auth failed: %s", strings.TrimSpace(line))
	}

	if _, err := fmt.Fprintf(w, "SIGNAL NEWNYM\r\n"); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	line, err = r.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "250") {
		return fmt.Errorf("tor control NEWNYM failed: %s", strings.TrimSpace(line))
	}
	return nil
}
