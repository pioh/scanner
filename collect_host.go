package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

type CollectedPort struct {
	Protocol       string // n1
	RecvQ          int    // n2
	SendQ          int    // n3
	LocalAddress   string // n4
	SrcPort        int    // n5
	ForeignAddress string // n6
	State          string // n7
	ProcessID      string // n8
	ProcessName    string // n9

}

type CollectedHost struct {
	Host  string
	IP    []net.IP
	Ports []CollectedPort
}

func (c *CollectedHost) parseNetstat(output string) (err error) {
	for n, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, "tcp") && !strings.HasPrefix(line, "udp") {
			continue
		}
		port := CollectedPort{}
		if err := port.parseNetstatLine(line); err != nil {
			return fmt.Errorf("failed parse %v line: %w", n, err)
		}
		c.Ports = append(c.Ports, port)
	}
	return nil
}

var netstatRegexp = regexp.MustCompile(`^(\w+)\s+(\d+)\s+(\d+)\s+(\S+):(\d+)\s+(\S+)\s+(\w+)?\s+(\d+)?/?-?(\S*.*\S+)?\s*$`)
var errFailedParseNetstatLine = errors.New("failed parse netstat line")
var errFailedParseIP = errors.New("failed parse ip")

func (p *CollectedPort) parseNetstatLine(line string) (err error) {
	groups := netstatRegexp.FindStringSubmatch(line)
	if groups == nil {
		return fmt.Errorf("%w: %v", errFailedParseNetstatLine, line)
	}
	p.Protocol = groups[1][0:3]

	if p.RecvQ, err = strconv.Atoi(groups[2]); err != nil {
		return fmt.Errorf("%w: %v: %+v: %v", errFailedParseNetstatLine, line, err, groups[2])
	}
	if p.SendQ, err = strconv.Atoi(groups[3]); err != nil {
		return fmt.Errorf("%w: %v: %+v: %v", errFailedParseNetstatLine, line, err, groups[3])
	}

	p.LocalAddress = groups[4] // n4

	if p.SrcPort, err = strconv.Atoi(groups[5]); err != nil {
		return fmt.Errorf("%w: %v: %+v: %v", errFailedParseNetstatLine, line, err, groups[5])
	}

	p.ForeignAddress = groups[6] // n6
	p.State = groups[7]          // n7
	p.ProcessID = groups[8]      // n8
	p.ProcessName = groups[9]    // n9

	return nil
}
func collectPorts(cli *ssh.Client, host *CollectedHost) error {
	log.Printf("collect ports on %v start", host.Host)
	defer log.Printf("collect ports on %v end", host.Host)
	s, err := cli.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	b, err := s.CombinedOutput("netstat -tulpn")

	if err != nil {
		return fmt.Errorf("failed netstat %v:\n%v\n%w", host.Host, string(b), err)
	}
	if err := host.parseNetstat(string(b)); err != nil {
		return fmt.Errorf("failed parse netstat for %v: %w", host.Host, err)
	}
	return nil
}
func collectIP(cli *ssh.Client, host *CollectedHost) error {
	log.Printf("collect ip on %v start", host.Host)
	defer log.Printf("collect ip on %v end", host.Host)

	s, err := cli.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	ip46, err := s.CombinedOutput(RE_IP + `ip  a | grep -oEi "inet6? [0-9a-z.:]+" | grep -Eo "$RE_IP"`)
	if err != nil {
		return fmt.Errorf("failed collect ip %v: %w:\n%v", host.Host, err, string(ip46))
	}

	allIPs := strings.Split(string(ip46), "\n")
	allIPs = append(allIPs, strings.Split(cli.RemoteAddr().String(), ":")[0])
	uniq := map[string]bool{}

	for _, ipStr := range allIPs {
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("%w: '%v'", errFailedParseIP, ipStr)
		}
		if isPrivate(ip) {
			continue
		}
		if uniq[ip.String()] {
			continue
		}
		uniq[ip.String()] = true
		host.IP = append(host.IP, ip)
	}
	return nil
}
func collectHostsBySSH(ctx context.Context, cfg config) ([]CollectedHost, error) {
	var hosts []CollectedHost
	m := sync.Mutex{}
	err := sshEachHost(ctx, cfg, func(cli *ssh.Client, host string) error {
		collectedHost := CollectedHost{
			Host: host,
		}
		if err := collectPorts(cli, &collectedHost); err != nil {
			return fmt.Errorf("failed collectPorts for host %v: %w", host, err)
		}
		if err := collectIP(cli, &collectedHost); err != nil {
			return fmt.Errorf("failed collectIP for host %v: %w", host, err)
		}
		m.Lock()
		defer m.Unlock()
		hosts = append(hosts, collectedHost)

		return nil
	})
	return hosts, err
}
