package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"time"

	"golang.org/x/crypto/ssh"

	"golang.org/x/sync/semaphore"
)

func sshEachHost(ctx context.Context, cfg config, job func(cli *ssh.Client, host string) error) error {
	g := ErrGroup{}
	for _, h := range cfg.Hosts {
		done := make(chan struct{}, 1)
		host := h
		g.Go(func() error {
			defer close(done)
			client, err := connectHost(ctx, cfg, host)
			if err != nil {
				return err
			}
			if err := job(client, host); err != nil {
				return err
			}
			return nil
		})
		go func() {
			for {
				select {
				case <-done:
					return
				case <-time.After(time.Second * 5):
					log.Printf("sshEachHost keep working on %v", host)
				}
			}
		}()
	}
	return g.Wait()
}
func sshEachAddr(ctx context.Context, cfg config, addr []string, job func(cli *ssh.Client, addr string) error) error {
	g := ErrGroup{}
	sem := semaphore.NewWeighted(30)
	for _, h := range addr {
		host := h
		if err := sem.Acquire(ctx, 1); err != nil {
			return err
		}
		g.Go(func() error {
			defer sem.Release(1)
			client, err := connect(ctx, cfg.signer, host)
			if err != nil {
				return err
			}
			if err := job(client, host); err != nil {
				return err
			}
			return nil
		})
	}
	return g.Wait()
}

func connectHost(ctx context.Context, cfg config, host string) (client *ssh.Client, err error) {
	for _, user := range cfg.Users {
		for _, port := range cfg.Ports {
			client, err = connect(ctx, cfg.signer, fmt.Sprintf("%v@%v:%v", user, host, port))
			if err == nil {
				log.Printf("ssh %v@%v:%v", user, host, port)
				return
			}
			if ctx.Err() != nil {
				return nil, fmt.Errorf("failed connect host %v: %w", host, ctx.Err())
			}
		}
	}
	return nil, fmt.Errorf("failed connect host %v: %w", host, err)
}

func connect(ctx context.Context, signer ssh.Signer, addr string) (*ssh.Client, error) {
	u, err := url.Parse("tcp://" + addr)
	if err != nil {
		return nil, fmt.Errorf("failed parse ssh addr %v: %w", addr, err)
	}

	config := &ssh.ClientConfig{
		User:            u.User.Username(),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
	}

	client, err := ssh.Dial("tcp", u.Host, config)
	if err != nil {
		return nil, fmt.Errorf("failed connect to %v: %+v", addr, err)
	}
	go func() {
		<-ctx.Done()
		if err := client.Close(); err != nil {
			log.Printf("failed connect to %v: %+v", addr, err)
		}
	}()

	return client, nil
}
