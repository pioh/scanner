package main

import (
	"context"
	"log"
	"time"
)

func main() {
	cfg := config{}
	if err := cfg.init(); err != nil {
		log.Printf("%+v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*2)
	defer cancel()

	hosts, err := collectHostsBySSH(ctx, cfg)
	if err != nil {
		log.Printf("%+v", err)
		return
	}

	cancel()

	ctx, cancel = context.WithTimeout(context.Background(), time.Minute*10)
	defer cancel()

	err = nmapAll(ctx, cfg, hosts)
	if err != nil {
		log.Printf("%+v", err)
		return
	}
}
