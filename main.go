package main

import (
	"context"
	"log"
	"os"
	"time"
)

func main() {
	cfg := config{}
	if err := cfg.init(); err != nil {
		log.Printf("%+v", err)
		os.Exit(1)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*2)
	hosts, scanError := collectHostsBySSH(ctx, cfg)
	cancel()

	ctx, cancel = context.WithTimeout(context.Background(), time.Minute*10)
	nmapErr := nmapAll(ctx, cfg, hosts)
	cancel()

	if scanError != nil {
		log.Printf("%+v", scanError)
	}

	if nmapErr != nil {
		log.Printf("%+v", nmapErr)
	}

	if scanError != nil || nmapErr != nil {
		os.Exit(1)
	}
}
