package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/olekukonko/tablewriter"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/semaphore"
)

type OpenPort struct {
	IP       net.IP
	Port     int
	Protocol string
	Extra    []string
}

func nmapAll(ctx context.Context, cfg config, targets []CollectedHost) error {
	wg := &sync.WaitGroup{}
	logSync := &sync.Mutex{}
	err := sshEachAddr(ctx, cfg, cfg.NmapFrom, func(cli *ssh.Client, addr string) error {
		wg.Add(1)
		err := nmap(ctx, cfg, addr, cli, targets, logSync, wg)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func nmap(ctx context.Context, cfg config, proxyAddr string, cli *ssh.Client, targets []CollectedHost, logSync sync.Locker, waitAll *sync.WaitGroup) error {
	g := ErrGroup{}
	m := sync.Mutex{}
	var openTargets []struct {
		CollectedHost
		ports []OpenPort
	}
	sem := semaphore.NewWeighted(30)
	for _, t := range targets {
		target := t
		if err := sem.Acquire(ctx, 1); err != nil {
			return err
		}
		g.Go(func() error {
			defer sem.Release(1)
			openPorts, err := nmapTarget(ctx, cfg, cli, target)
			if err != nil {
				return err
			}
			m.Lock()
			defer m.Unlock()
			openTargets = append(openTargets, struct {
				CollectedHost
				ports []OpenPort
			}{CollectedHost: target, ports: openPorts})
			return nil
		})
	}
	err := g.Wait()

	waitAll.Done()
	waitAll.Wait()
	logSync.Lock()
	defer logSync.Unlock()

	outDir := ""
	if cfg.Output != "" {
		outDir = cfg.Output
		if cfg.OutputByTime {
			path.Join(outDir, time.Now().Format("2006-01-02T15:04"))
		}
		if err := os.MkdirAll(outDir, os.ModePerm); err != nil {
			return fmt.Errorf("failed create output directory '%v': %w", outDir, err)
		}
	}

	for _, t := range openTargets {
		fmt.Printf("\n%v from %v:\n", t.Host, proxyAddr)
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Port", "Proto", "IP"})
		var output []string
		for _, o := range t.ports {
			for _, t := range t.Ports {
				if t.Protocol == o.Protocol && t.SrcPort == o.Port {
					if t.ProcessName != "" && t.ProcessName != "-" {
						o.Extra = append(o.Extra, t.ProcessName)
					}
				}
			}
			cols := append([]string{
				strconv.Itoa(o.Port), o.Protocol, o.IP.String(),
			}, o.Extra...)

			table.Append(cols)
			if outDir != "" {
				output = append(output, strings.Join(cols, ","))
			}
			// log.Printf("%v/%v/%v/%v", o.Port, o.Protocol, o.IP, strings.Join(o.Extra, "/"))
		}
		table.Render()
		if outDir != "" {
			fname := path.Join(outDir, fmt.Sprintf("%v.csv", t.Host))
			if err := ioutil.WriteFile(fname, []byte(strings.Join(output, "\n")), 0640); err != nil {
				return fmt.Errorf("failed write result to %v: %w", fname, err)
			}
		}
	}

	return err
}

var nmapHostRegexp = regexp.MustCompile(`^Host: (\S+)\s+\(\)\s+Ports:\s+(.*///)\s*(Ignored.*)?$`)
var nmapPorts = regexp.MustCompile(`^(\d+)/([^/]+)/([^/]+)/([^/]*)/([^/]*)/([^/]*)/([^/]*)/([^/]*)$`)

func nmapTarget(ctx context.Context, cfg config, cli *ssh.Client, target CollectedHost) ([]OpenPort, error) {
	s, err := cli.NewSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	cmd := strings.Join([]string{
		cmdUDP4(target),
		cmdUDP6(target),
		cmdTCP4(target),
		cmdTCP6(target),
	}, "")
	fmt.Printf("\nnmap %v start (%v ips, %v ports)\n%v", target.Host, len(target.IP), len(target.Ports), cmd)
	outReader, stdout := io.Pipe()
	stderr := &bytes.Buffer{}
	s.Stdout = stdout
	s.Stderr = stderr

	if err := s.Start(cmd); err != nil {
		return nil, fmt.Errorf("failed nmap %v:\n%w:\n%v", target.Host, err, stderr.String())
	}

	g := ErrGroup{}
	g.Go(func() error {
		defer stdout.Close()
		if err := s.Wait(); err != nil {
			return fmt.Errorf("failed wait for ssh: %w:\n%v", err, stderr.String())
		}
		return nil
	})

	var openPorts []OpenPort
	outScanner := bufio.NewScanner(outReader)
	for outScanner.Scan() {
		line := outScanner.Text()
		if strings.HasPrefix(line, "#") {
			log.Printf(line[1:])
		}
		if line == "" || line[0] == '#' || !strings.Contains(line, "Ports:") {
			continue
		}
		groups := nmapHostRegexp.FindStringSubmatch(line)
		if groups == nil {
			return nil, fmt.Errorf("failed match nmap line for host %v", line)
		}
		ip := net.ParseIP(groups[1])
		if ip == nil {
			return nil, fmt.Errorf("failed parse ip '%v' from: %v", groups[1], line)
		}
		portsStr := groups[2]
		ports := strings.Split(portsStr, ", ")
		for _, portStr := range ports {
			var err error
			o := OpenPort{
				IP: ip,
			}
			groups := nmapPorts.FindStringSubmatch(portStr)

			if o.Port, err = strconv.Atoi(groups[1]); err != nil {
				return nil, fmt.Errorf("failed parse port '%v' from: %v", groups[1], portStr)
			}
			o.Protocol = groups[3]
			state := groups[2]
			if state == "open|filtered" {
				continue
			}
			o.Extra = append(o.Extra, state)
			o.Extra = append(o.Extra, groups[5])
			for _, g := range []int{4, 6, 7, 8} {
				if groups[g] != "" {
					o.Extra = append(o.Extra, groups[g])
				}
			}
			openPorts = append(openPorts, o)
		}
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	if err := outScanner.Err(); err != nil {
		return nil, fmt.Errorf("failed scan ssh: %w:\n%v", err, stderr.String())
	}

	return openPorts, nil
}

// nmap --open -Pn -n -oG - -sU -p 500,53,4500,54,8125,49167 -4 95.217.110.235

func cmdUDP6(target CollectedHost) string {
	var ports []string
	var ips []string
	for _, port := range target.Ports {
		ports = append(ports, strconv.Itoa(port.SrcPort))
	}
	for _, ip := range target.IP {
		if ip.To4() == nil {
			ips = append(ips, ip.To16().String())
		}
	}
	if len(ips)*len(ports) == 0 {
		return ""
	}
	ips = uniq(ips)
	ports = uniq(ports)
	var out []string
	for _, ip := range ips {
		out = append(out, `nmap --open -Pn -n -oG - -sU -p `+strings.Join(ports, ",")+` -6 `+ip+"\n")
	}
	return strings.Join(out, "")
}
func cmdUDP4(target CollectedHost) string {
	var ports []string
	var ips []string
	for _, port := range target.Ports {
		ports = append(ports, strconv.Itoa(port.SrcPort))
	}
	for _, ip := range target.IP {
		if ip.To4() != nil {
			ips = append(ips, ip.To4().String())
		}
	}
	if len(ips)*len(ports) == 0 {
		return ""
	}
	ips = uniq(ips)
	ports = uniq(ports)
	var out []string
	for _, ip := range ips {
		out = append(out, `nmap --open -Pn -n -oG - -sU -p `+strings.Join(ports, ",")+` -4 `+ip+"\n")
	}
	return strings.Join(out, "")
}
func cmdTCP4(target CollectedHost) string {
	var ports []string
	var ips []string
	for _, port := range target.Ports {
		ports = append(ports, strconv.Itoa(port.SrcPort))
	}
	for _, ip := range target.IP {
		if ip.To4() != nil {
			ips = append(ips, ip.To4().String())
		}
	}
	if len(ips)*len(ports) == 0 {
		return ""
	}
	ips = uniq(ips)
	ports = uniq(ports)
	var out []string
	for _, ip := range ips {
		out = append(out, `nmap --open -Pn -n -oG - -sT -p `+strings.Join(ports, ",")+` -4 `+ip+"\n")
	}
	return strings.Join(out, "")
}
func cmdTCP6(target CollectedHost) string {
	var ports []string
	var ips []string
	for _, port := range target.Ports {
		ports = append(ports, strconv.Itoa(port.SrcPort))
	}
	for _, ip := range target.IP {
		if ip.To4() == nil {
			ips = append(ips, ip.To16().String())
		}
	}
	if len(ips)*len(ports) == 0 {
		return ""
	}
	ips = uniq(ips)
	ports = uniq(ports)
	var out []string
	for _, ip := range ips {
		out = append(out, `nmap --open -Pn -n -oG - -sT -p `+strings.Join(ports, ",")+` -6 `+ip+"\n")
	}
	return strings.Join(out, "")
}

func uniq(items []string) []string {
	m := map[string]bool{}
	for _, it := range items {
		m[it] = true
	}
	items = []string{}
	for it := range m {
		items = append(items, it)
	}
	sort.Strings(items)
	return items
}
