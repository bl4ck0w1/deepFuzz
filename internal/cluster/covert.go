package cluster

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
	"github.com/bl4ck0w1/deepFuzz/internal/core"
	"github.com/miekg/dns"
	"github.com/google/uuid"
)

type CovertChannel struct {
	dnsServer    string 
	domain       string 
	client       *dns.Client
	nodeID       string
	pollInterval time.Duration
	commandChan  chan core.FuzzTask
	seen         map[string]struct{} 
}

func NewCovertChannel(dnsServer, domain string) (*CovertChannel, error) {
	if dnsServer == "" || domain == "" {
		return nil, fmt.Errorf("dnsServer and domain are required")
	}
	if !strings.Contains(dnsServer, ":") {
		dnsServer = dnsServer + ":53"
	}
	cc := &CovertChannel{
		dnsServer:    dnsServer,
		domain:       dns.Fqdn(domain),
		client:       &dns.Client{Net: "udp", Timeout: 5 * time.Second, UDPSize: 1232},
		nodeID:       "n-" + uuid.New().String()[:8],
		pollInterval: 6 * time.Second,
		commandChan:  make(chan core.FuzzTask, 256),
		seen:         make(map[string]struct{}, 256),
	}
	return cc, nil
}

func (cc *CovertChannel) Start(ctx context.Context) {
	go cc.pollCommands(ctx)
}

func (cc *CovertChannel) pollCommands(ctx context.Context) {
	t := time.NewTicker(cc.pollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			name := fmt.Sprintf("cmd.%s.%s", cc.nodeID, cc.domain)
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
			in, _, err := cc.client.Exchange(msg, cc.dnsServer)
			if err != nil || in == nil || len(in.Answer) == 0 {
				continue
			}
			for _, rr := range in.Answer {
				txt, ok := rr.(*dns.TXT)
				if !ok {
					continue
				}
				payload := strings.Join(txt.Txt, "")
				if payload == "" {
					continue
				}
				if _, seen := cc.seen[payload]; seen {
					continue
				}
				cc.seen[payload] = struct{}{}

				task, err := cc.decodeTaskPayload(payload)
				if err != nil {
					continue
				}
				select {
				case cc.commandChan <- task:
				default:
					select {
					case <-cc.commandChan:
					default:
					}
					cc.commandChan <- task
				}
			}
		}
	}
}

func (cc *CovertChannel) GetTask() <-chan core.FuzzTask {
	return cc.commandChan
}

func (cc *CovertChannel) SendResult(result core.FuzzResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	encoded := hex.EncodeToString(data)
	labels := chunkLabel(encoded, 50) 
	subdomain := fmt.Sprintf("ex.%s.%s.%s", cc.nodeID, strings.Join(labels, "."), cc.domain)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(subdomain), dns.TypeTXT)
	msg.RecursionDesired = true

	conn, err := net.Dial("udp", cc.dnsServer)
	if err != nil {
		return err
	}
	defer conn.Close()

	wire, err := msg.Pack()
	if err != nil {
		return err
	}
	_, err = conn.Write(wire)
	return err
}

func (cc *CovertChannel) decodeTaskPayload(s string) (core.FuzzTask, error) {
	var task core.FuzzTask
	if raw, err := hex.DecodeString(s); err == nil {
		if json.Unmarshal(raw, &task) == nil {
			return task, nil
		}
	}
	if raw, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		if json.Unmarshal(raw, &task) == nil {
			return task, nil
		}
	}
	return task, fmt.Errorf("unable to decode command")
}

func (df *DarkFleetCoordinator) EnableCovertChannel(dnsServer, domain string) {
	channel, err := NewCovertChannel(dnsServer, domain)
	if err != nil {
		return
	}
	go channel.Start(context.Background())

	go func() {
		for task := range channel.GetTask() {
			_ = df.DistributeTask(task)
		}
	}()
}

func chunkLabel(s string, max int) []string {
	if max <= 0 {
		max = 63
	}
	var out []string
	for len(s) > 0 {
		if len(s) <= max {
			out = append(out, s)
			break
		}
		out = append(out, s[:max])
		s = s[max:]
	}
	return out
}
