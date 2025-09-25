package modules

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/ssh"
)

type SSHFlags struct {
	zgrab2.BaseFlags  `group:"Basic Options"`
	ClientID          string `long:"client" description:"Specify the client ID string to use." default:"SSH-2.0-Go"`
	KexAlgorithms     string `long:"kex-algorithms" description:"A comma-separated list of kex algorithms to offer in descending precedence." default:"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1"`
	HostKeyAlgorithms string `long:"host-key-algorithms" description:"A comma-separated list of host key algorithms to offer in descending precedence." default:"ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss,ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com"`
	Ciphers           string `long:"ciphers" description:"A comma-separated list of cipher algorithms to offer in descending precedence." default:"chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,arcfour256,arcfour128,arcfour,3des-cbc"`
	MACs              string `long:"macs" description:"A comma-separated list of MAC algorithms to offer in descending precedence." default:"hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha1,hmac-sha1-96"`
	CollectExtensions bool   `long:"extensions" description:"Complete the SSH transport layer protocol to collect SSH extensions as per RFC 8308 (if any)."`
	CollectUserAuth   bool   `long:"userauth" description:"Use the 'none' authentication request to see what userauth methods are allowed."`
	GexMinBits        uint   `long:"gex-min-bits" description:"The minimum number of bits for the DH GEX prime." default:"1024"`
	GexMaxBits        uint   `long:"gex-max-bits" description:"The maximum number of bits for the DH GEX prime." default:"8192"`
	GexPreferredBits  uint   `long:"gex-preferred-bits" description:"The preferred number of bits for the DH GEX prime." default:"2048"`
	HelloOnly         bool   `long:"hello-only" description:"Limit scan to the initial hello message."`
}

type SSHModule struct {
}

type SSHScanner struct {
	config            *SSHFlags
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

func init() {
	var sshModule SSHModule
	_, err := zgrab2.AddCommand("ssh", "Secure Shell (SSH)", sshModule.Description(), 22, &sshModule)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *SSHModule) NewFlags() any {
	return new(SSHFlags)
}

func (m *SSHModule) NewScanner() zgrab2.Scanner {
	return new(SSHScanner)
}

// Description returns an overview of this module.
func (m *SSHModule) Description() string {
	return "Fetch an SSH server banner and collect key exchange information"
}

func (f *SSHFlags) Validate(_ []string) error {
	return nil
}

func (f *SSHFlags) Help() string {
	return ""
}

func (s *SSHScanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*SSHFlags)
	s.config = f
	s.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

func (s *SSHScanner) InitPerSender(senderID int) error {
	return nil
}

func (s *SSHScanner) GetName() string {
	return s.config.Name
}

func (s *SSHScanner) GetTrigger() string {
	return s.config.Trigger
}

func (s *SSHScanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	data := new(ssh.HandshakeLog)
	portStr := strconv.Itoa(int(target.Port))
	rhost := net.JoinHostPort(target.Host(), portStr)

	sshConfig := new(ssh.ClientConfig)
	sshConfig.Timeout = s.config.ConnectTimeout
	sshConfig.ConnLog = data
	sshConfig.ClientVersion = s.config.ClientID
	sshConfig.HelloOnly = s.config.HelloOnly
	if err := sshConfig.SetHostKeyAlgorithms(s.config.HostKeyAlgorithms); err != nil {
		log.Fatal(err)
	}
	if err := sshConfig.SetKexAlgorithms(s.config.KexAlgorithms); err != nil {
		log.Fatal(err)
	}
	if err := sshConfig.SetCiphers(s.config.Ciphers); err != nil {
		log.Fatal(err)
	}
	if err := sshConfig.SetMACs(s.config.MACs); err != nil {
		log.Fatal(err)
	}
	sshConfig.Verbose = s.config.Verbose
	sshConfig.CollectExtensions = s.config.CollectExtensions
	sshConfig.CollectUserAuth = s.config.CollectUserAuth
	sshConfig.DontAuthenticate = true // Ethical scanning only, never try to authenticate
	sshConfig.GexMinBits = s.config.GexMinBits
	sshConfig.GexMaxBits = s.config.GexMaxBits
	sshConfig.GexPreferredBits = s.config.GexPreferredBits
	sshConfig.BannerCallback = func(banner string) error {
		data.Banner = strings.TrimSpace(banner)
		return nil
	}
	sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	// Implementation taken from lib/ssh/client.go
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		err = fmt.Errorf("failed to dial target %s: %w", target.String(), err)
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	if s.config.ConnectTimeout != 0 {
		err = conn.SetDeadline(time.Now().Add(s.config.ConnectTimeout))
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("failed to set connection deadline: %w", err)
		}
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, rhost, sshConfig)
	if err != nil {
		return zgrab2.SCAN_HANDSHAKE_ERROR, nil, fmt.Errorf("failed to create SSH client connection: %w", err)
	}
	sshClient := ssh.NewClient(c, chans, reqs)
	defer func() {
		err = sshClient.Close()
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Errorf("error closing SSH client for target %s: %v", target.String(), err)
		}
	}()

	// TODO FIXME: Distinguish error types
	status := zgrab2.TryGetScanStatus(err)
	return status, data, err
}

// Protocol returns the protocol identifer for the scanner.
func (s *SSHScanner) Protocol() string {
	return "ssh"
}

func (s *SSHScanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return s.dialerGroupConfig
}

// GetScanMetadata returns any metadata on the scan itself from this module.
func (s *SSHScanner) GetScanMetadata() any {
	return nil
}
