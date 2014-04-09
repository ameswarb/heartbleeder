package main

import (
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/titanous/heartbleeder/tls"
)

const (
	STATE_NO_HEARTBEAT = 0
	STATE_UNKNOWN      = 1
	STATE_TIMEOUT      = 2
	STATE_CONN_CLOSED  = 3
	STATE_CONN_REFUSED = 4
	STATE_VUNERABLE    = 255
)

type Target struct {
	Host         string
	OriginalHost string
	LastChecked  time.Time
	TimeVerified time.Time
	State        int
}

func main() {
	timeout := flag.Duration("timeout", 5*time.Second, "Timeout after sending heartbeat")
	hostfile := flag.String("f", "", "Path to a newline seperated file with hosts or ips")
	workers := flag.Int("workers", runtime.NumCPU()*10, "Number of workers to scan hosts with, only used with hosts flag")
	flag.Usage = func() {
		log.Printf("Usage: %s [options] host[:443]\n", os.Args[0])
		log.Println("Options:")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *hostfile != "" {
		checkMultiHosts(hostfile, timeout, *workers)
	} else {
		checkSingleHost(flag.Arg(0), timeout)
	}
}

func checkSingleHost(host string, timeout *time.Duration) {
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	ret, err := checkHeartbeat(host, timeout)
	log.Fatal(err)
	os.Exit(ret)
}

func checkHeartbeat(host string, timeout *time.Duration) (int, error) {
	var err error

	c, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Printf("Error connecting to %s: %s\n", host, err)
		return STATE_CONN_REFUSED, err
	}

	err = c.WriteHeartbeat(1, nil)
	if err == tls.ErrNoHeartbeat {
		log.Printf("SECURE - %s does not have the heartbeat extension enabled\n", host)
		return STATE_NO_HEARTBEAT, err
	}

	if err != nil {
		log.Println("UNKNOWN - Heartbeat enabled, but there was an error writing the payload:", err)
		return STATE_UNKNOWN, err
	}

	readErr := make(chan error)
	go func() {
		_, _, err := c.ReadHeartbeat()
		readErr <- err
	}()

	select {
	case err := <-readErr:
		if err == nil {
			log.Printf("VULNERABLE - %s has the heartbeat extension enabled and is vulnerable to CVE-2014-0160\n", host)
			return STATE_VUNERABLE, err
		}
		log.Printf("SECURE - %s has heartbeat extension enabled but is not vulnerable\n", host)
		log.Printf("This error happened while reading the response to the malformed heartbeat (almost certainly a good thing): %q\n", err)
		return STATE_CONN_CLOSED, err
	case <-time.After(*timeout):
	}

	log.Printf("SECURE - %s has the heartbeat extension enabled, but timed out after a malformed heartbeat (this likely means that it is not vulnerable)\n", host)
	return STATE_TIMEOUT, err
}

func checkMultiHosts(hostfile *string, timeout *time.Duration, numWorkers int) {
	hosts := readHosts(*hostfile)

	dispatch := make(chan *Target, numWorkers*2)
	for x := 0; x < numWorkers; x++ {
		go scanner(dispatch, timeout)
	}

	t := time.NewTicker(10 * time.Second)
	go func() {
		for {
			for _, t := range hosts {
				if t.State > 0 {
					dispatch <- t
				}
			}
			<-t.C
		}
	}()

	handleHTTP(hosts)
}

func handleHTTP(hosts []*Target) {
	// I see you judging me... The bible says don't judge and stuff
	// not that the Bible ever stopped you before...
	t, _ := template.New("foo").Parse(`<td>{{.OriginalHost}}</td><td>{{.Host}}</td><td>{{.LastChecked}}</td>`)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// Look, I don't HTML or do templates much.  I regret nothing
			fmt.Fprintf(w, `<html><header><link rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.1.1/css/bootstrap.min.css">`)
			fmt.Fprintf(w, `<body><table class="table table-hover table-bordered">`)
			fmt.Fprintf(w, "<p> Number of hosts %d</p>", len(hosts))
			fmt.Fprintf(w, "<tr><th>Target</th><th>IP</th><th>Checked</th>\n")
			var status string
			// Everyone can hear baby jesus right now, and yes those are tears of disappointment.
			for _, target := range hosts {
				switch target.State {
				case STATE_NO_HEARTBEAT, STATE_CONN_CLOSED:
					status = "success"
				case STATE_TIMEOUT:
					status = "warning"
				case STATE_VUNERABLE:
					status = "danger"
				case STATE_CONN_REFUSED:
					status = "info"
				default:
					status = "active"
				}
				fmt.Fprintf(w, `<tr class="%s">`, status)
				t.Execute(w, target)
				fmt.Fprintf(w, `</tr>`)
			}
			fmt.Fprintf(w, "</table></body></html>\n")
		}

	})
	log.Fatal(http.ListenAndServe(":5779", nil))
}

func scanner(source chan *Target, timeout *time.Duration) {
	for target := range source {
		state, err := checkHeartbeat(target.Host, timeout)
		if err != nil {
			log.Printf("%s", err)
		}

		target.LastChecked = time.Now().UTC()
		target.State = state

		if target.State == STATE_NO_HEARTBEAT || target.State == STATE_CONN_CLOSED {
			target.TimeVerified = target.LastChecked
		}
	}
}

func NewTarget(hostaddr string) []*Target {
	host, port, err := net.SplitHostPort(hostaddr)
	if err != nil {
		host = hostaddr
		port = "443"
	}

	hostport := net.JoinHostPort(host, port)
	if net.ParseIP(host) != nil {
		return []*Target{&Target{Host: hostport, OriginalHost: hostport, State: STATE_UNKNOWN}}
	}

	addrs, err := net.LookupIP(host)
	if err != nil {
		log.Printf("Failed (%s) %s", host, err)
		return []*Target{}
	}

	// Add a target for each IP so we can get an accurate view
	targets := []*Target{}
	for _, addr := range addrs {
		targets = append(targets, &Target{Host: net.JoinHostPort(addr.String(), port), OriginalHost: hostport, State: STATE_UNKNOWN})
	}
	return targets
}

func readHosts(hostfile string) []*Target {
	targets := []*Target{}

	contents, err := ioutil.ReadFile(hostfile)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	for _, line := range strings.Split(string(contents), "\n") {
		targets = append(targets, NewTarget(line)...)
	}

	return targets
}
