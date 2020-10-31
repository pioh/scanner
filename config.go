package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/go-yaml/yaml"
	"golang.org/x/crypto/ssh"
)

type config struct {
	Users []string
	Hosts []string
	Ports []uint16
	Key   string

	NmapFrom []string `yaml:"nmapFrom"`

	signer ssh.Signer
}

func (cfg *config) init() error {
	if err := cfg.readFromArgsFiles(); err != nil {
		return err
	}
	if err := cfg.initSSHKey(); err != nil {
		return err
	}
	return nil
}

func (cfg *config) readFromArgsFiles() error {
	for _, configFileName := range os.Args[1:] {
		configSource, err := ioutil.ReadFile(configFileName)
		if err != nil {
			return err
		}
		if err := yaml.UnmarshalStrict(configSource, &cfg); err != nil {
			return err
		}
	}
	if resultConfig, err := yaml.Marshal(*cfg); err != nil {
		return err
	} else {
		log.Printf("config:\n%v\n", string(resultConfig))
	}
	return nil
}
func (cfg *config) initSSHKey() error {
	key, err := ioutil.ReadFile(cfg.Key)
	if err != nil {
		return err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return err
	}

	cfg.signer = signer
	return nil
}
