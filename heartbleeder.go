package main

import (
	"flag"
	"fmt"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/nu7hatch/gouuid"
	"github.com/titanous/heartbleeder/tls"
)

const (
	ResultSecure = iota
	ResultUnknown
	ResultTimeout
	ResultConnectionRefused
	ResultVunerable
)

type Target struct {
	Uuid		 string
	Host         string
	OriginalHost string
	LastChecked  *time.Time
	TimeVerified *time.Time
	LastError    error
	State        int
}

func main() {
	timeout := flag.Duration("timeout", 5*time.Second, "Timeout after sending heartbeat")
	hostFile := flag.String("f", "", "Path to a newline seperated file with hosts or ips")
	workers := flag.Int("workers", runtime.NumCPU()*10, "Number of workers to scan hosts with, only used with hostfile flag")
	retryDelay := flag.Duration("retry", 10*time.Second, "Seconds to wait before retesting a host after an unfavorable response")
	listen := flag.String("l", "localhost:5000", "Host:port to serve heartbleed page")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] host[:443]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *hostFile != "" {
		checkMultiHosts(*hostFile, *timeout, *retryDelay, *workers, *listen)
	} else {
		checkSingleHost(flag.Arg(0), *timeout)
	}
}

func checkSingleHost(host string, timeout time.Duration) {
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	ret, _ := checkHeartbeat(host, timeout)
	os.Exit(ret)
}

func checkHeartbeat(host string, timeout time.Duration) (int, error) {
	c, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Printf("Error connecting to %s: %s\n", host, err)
		return ResultConnectionRefused, err
	}

	err = c.WriteHeartbeat(1, nil)
	if err == tls.ErrNoHeartbeat {
		log.Printf("SECURE(%s) - does not have the heartbeat extension enabled", host)
		return ResultSecure, err
	}

	if err != nil {
		log.Printf("UNKNOWN(%s) - Heartbeat enabled, but there was an error writing the payload:", host, err)
		return ResultUnknown, err
	}

	readErr := make(chan error)
	go func() {
		_, _, err := c.ReadHeartbeat()
		readErr <- err
	}()

	select {
	case err := <-readErr:
		if err == nil {
			log.Printf("VULNERABLE(%s) - has the heartbeat extension enabled and is vulnerable to CVE-2014-0160", host)
			return ResultVunerable, err
		}
		log.Printf("SECURE(%s) has heartbeat extension enabled but is not vulnerable: %q", host, err)
		return ResultSecure, err
	case <-time.After(timeout):
	}

	log.Printf("SECURE(%s) - has the heartbeat extension enabled, but timed out after a malformed heartbeat (this likely means that it is not vulnerable)", host)
	return ResultTimeout, err
}

func checkMultiHosts(hostFile string, timeout, retryDelay time.Duration, numWorkers int, listenAddr string) {
	hosts := readHosts(hostFile)

	dispatch := make(chan *Target, len(hosts))
	for x := 0; x < numWorkers; x++ {
		go scanner(dispatch, timeout, retryDelay)
	}

	// Seed hosts to scan
	for _, t := range hosts {
		dispatch <- t
	}

	handleHTTP(hosts, listenAddr)
}

func handleHTTP(hosts []*Target, listenAddr string) {
	// I see you judging me... The bible says don't judge and stuff
	// not that the Bible ever stopped you before...
	http.HandleFunc("/api/host", func(w http.ResponseWriter, r *http.Request) {

		if r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			js, err := json.Marshal(hosts)
			if err != nil {
			    http.Error(w, err.Error(), http.StatusInternalServerError)
			    return
			}
			w.Write(js)
		}
	})
	http.Handle("/", http.FileServer(http.Dir("interfaces/angular")))
	log.Println("Serving Heartbleed status on", listenAddr)
	http.ListenAndServe(listenAddr, nil)
}

func scanner(source chan *Target, timeout, retryDelay time.Duration) {
	for target := range source {
		state, err := checkHeartbeat(target.Host, timeout)
		now := time.Now().UTC()
		target.LastChecked = &now
		target.State = state
		target.LastError = err

		if target.State == ResultSecure {
			target.TimeVerified = target.LastChecked
			continue
		}

		// put this back on the channel after a timeout but don't block the scanner
		go func() {
			time.Sleep(retryDelay)
			source <- target
		}()
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
		return []*Target{&Target{Host: hostport, OriginalHost: hostport, State: ResultUnknown}}
	}

	addrs, err := net.LookupIP(host)
	if err != nil {
		log.Printf("Failed DNS lookup on %s. Not adding to scanner - %s", host, err)
		return nil
	}

	// Add a target for each IP so we can get an accurate view
	targets := make([]*Target, len(addrs))
	for i, addr := range addrs {
		// UUID stuff is used on the angular app so that it has a way to compare
		// objects and see if they've changed
		u4, err := uuid.NewV4()
		if err != nil {
		    fmt.Println("error:", err)
		}
		targets[i] = &Target{Host: net.JoinHostPort(addr.String(), port), Uuid: u4.String(), OriginalHost: hostport, State: ResultUnknown}
	}
	return targets
}

func readHosts(hostFile string) []*Target {
	var targets []*Target

	contents, err := ioutil.ReadFile(hostFile)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	for _, line := range strings.Split(string(contents), "\n") {
		line := strings.TrimSpace(line)
		if line == "" {
			continue
		}
		targets = append(targets, NewTarget(line)...)
	}

	return targets
}
