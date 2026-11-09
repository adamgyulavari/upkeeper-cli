package collect

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// Prober checks published ports (A-05): a TCP connect, then `GET /` without
// following redirects. Both have a short timeout.
type Prober struct {
	Timeout time.Duration
}

func (p Prober) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return 2 * time.Second
}

// ProbeTarget picks the address to probe for a published port: the bind IP
// if the port was published on one address, otherwise 127.0.0.1.
func ProbeTarget(bindIP string, port int) string {
	ip := bindIP
	switch ip {
	case "", "0.0.0.0", "::":
		ip = "127.0.0.1"
	}
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

// Probe returns whether addr accepts TCP and, if it speaks HTTP, the status of GET /.
func (p Prober) Probe(ctx context.Context, addr string) (open bool, status int) {
	d := net.Dialer{Timeout: p.timeout()}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, 0
	}
	conn.Close()

	client := &http.Client{
		Timeout: p.timeout(),
		Transport: &http.Transport{
			Proxy:             nil, // local probe: never through a proxy
			DialContext:       d.DialContext,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/", nil)
	if err != nil {
		return true, 0
	}
	req.Header.Set("User-Agent", "upkeeper-probe")
	resp, err := client.Do(req)
	if err != nil {
		return true, 0
	}
	resp.Body.Close()
	return true, resp.StatusCode
}

// ProbeAll fills TCPOpen and HTTPStatus on every published TCP port.
func (p Prober) ProbeAll(ctx context.Context, projects []protocol.Project, facts DockerFacts) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for pi := range projects {
		for si := range projects[pi].Services {
			svc := &projects[pi].Services[si]
			bind := facts.Services[projects[pi].Name+"/"+svc.Name].BindIPs
			for k := range svc.Ports {
				port := &svc.Ports[k]
				if port.Proto != "tcp" {
					continue
				}
				addr := ProbeTarget(bind[strconv.Itoa(port.HostPort)+"/tcp"], port.HostPort)
				wg.Add(1)
				go func() {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					port.TCPOpen, port.HTTPStatus = p.Probe(ctx, addr)
				}()
			}
		}
	}
	wg.Wait()
}
