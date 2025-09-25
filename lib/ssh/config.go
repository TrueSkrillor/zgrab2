package ssh

import (
	"errors"
	"fmt"
	"strings"
)

func MakeSSHConfig() *ClientConfig {
	ret := new(ClientConfig)
	ret.KeyExchanges = supportedKexAlgos
	ret.HostKeyAlgorithms = supportedHostKeyAlgos
	ret.Ciphers = supportedCiphers
	ret.MACs = supportedMACs
	return ret
}

func (c *ClientConfig) SetKexAlgorithms(value string) error {
	algs, err := validateAlgorithms(value, supportedKexAlgos)
	if err != nil {
		return err
	}
	c.KeyExchanges = algs
	return nil
}

func (c *ClientConfig) SetHostKeyAlgorithms(value string) error {
	algs, err := validateAlgorithms(value, supportedHostKeyAlgos)
	if err != nil {
		return err
	}
	c.HostKeyAlgorithms = algs
	return nil
}

func (c *ClientConfig) SetCiphers(value string) error {
	algs, err := validateAlgorithms(value, supportedCiphers)
	if err != nil {
		return err
	}
	c.Ciphers = algs
	return nil
}

func (c *ClientConfig) SetMACs(value string) error {
	algs, err := validateAlgorithms(value, supportedMACs)
	if err != nil {
		return err
	}
	c.MACs = algs
	return nil
}

func validateAlgorithms(value string, supported []string) ([]string, error) {
	var algs []string
	for _, alg := range strings.Split(value, ",") {
		isValid := contains(supported, alg)
		if !isValid {
			return nil, errors.New(fmt.Sprintf(`algorithm not supported: "%s"`, alg))
		}
		algs = append(algs, alg)
	}
	return algs, nil
}
