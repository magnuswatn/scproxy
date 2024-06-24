package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/smallstep/truststore"
	"howett.net/plist"
)

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func getCertFolder() string {

	var dir string
	switch {
	case runtime.GOOS == "windows":
		dir = os.Getenv("LocalAppData")
	case os.Getenv("XDG_DATA_HOME") != "":
		dir = os.Getenv("XDG_DATA_HOME")
	case runtime.GOOS == "darwin":
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, "Library", "Application Support")
	default: // Unix
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, ".local", "share")
	}
	return filepath.Join(dir, "scproxy")
}

func getCertAndKeyPath() (string, string) {
	certFolder := getCertFolder()

	certPath := filepath.Join(certFolder, "cert.pem")
	keyPath := filepath.Join(certFolder, "key.pem")

	return certPath, keyPath
}

func installServiceOnLinux() {

	executable, err := os.Executable()
	fatalIfErr(err, "failed to get executable path")

	systemdFile := `[Unit]
Description=Buypass compatible smart card proxy
Documentation=https://github.com/magnuswatn/scproxy

[Service]
Type=exec
ExecStart="%s"
IPAddressDeny=any
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native
NoNewPrivileges=yes
KeyringMode=private
UMask=0177

[Install]
WantedBy=default.target
`

	serviceFolder := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user")
	serviceFile := filepath.Join(serviceFolder, "scproxy.service")

	err = os.MkdirAll(serviceFolder, 0700)
	fatalIfErr(err, "failed to create systemd folder")

	executable = strings.ReplaceAll(executable, `\`, `\\`)
	executable = strings.ReplaceAll(executable, `"`, `\"`)
	finishedSystemdFile := fmt.Sprintf(systemdFile, executable)
	err = os.WriteFile(serviceFile, []byte(finishedSystemdFile), 0644)
	fatalIfErr(err, "failed to write systemd file")

	err = exec.Command("systemctl", "--user", "daemon-reload").Run()
	fatalIfErr(err, "failed to reload systemd")
	err = exec.Command("systemctl", "--user", "start", "scproxy").Run()
	fatalIfErr(err, "failed to start service")
}

func uninstallServiceOnLinux() {

	serviceIsRunning := true

	log.Printf("Checking if service is installed")
	var e *exec.ExitError
	err := exec.Command("systemctl", "--user", "status", "scproxy").Run()
	if err != nil {
		if errors.As(err, &e) {
			if e.ExitCode() == 4 {
				log.Printf("Service not installed")
				return
			} else if e.ExitCode() == 3 {
				serviceIsRunning = false
			} else {
				fatalIfErr(err, "failed to check service status")
			}
		} else {
			fatalIfErr(err, "failed to check service status")
		}
	}

	if serviceIsRunning {
		log.Printf("Stopping service")
		err = exec.Command("systemctl", "--user", "stop", "scproxy").Run()
		fatalIfErr(err, "failed to stop service")
	}

	log.Printf("Uninstalling service")
	serviceFolder := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user")
	serviceFile := filepath.Join(serviceFolder, "scproxy.service")

	err = os.Remove(serviceFile)
	fatalIfErr(err, "failed to remove systemd file")

	err = exec.Command("systemctl", "--user", "daemon-reload").Run()
	fatalIfErr(err, "failed to reload systemd")
}

func installServiceOnDarwin() {

	executable, err := os.Executable()
	fatalIfErr(err, "failed to get executable path")

	libraryFolder := filepath.Join(os.Getenv("HOME"), "Library")
	logsFolder := filepath.Join(libraryFolder, "Logs")

	type serviceHeader struct {
		Label            string   `plist:"Label"`
		ProgramArguments []string `plist:"ProgramArguments"`
		KeepAlive        bool     `plist:"KeepAlive"`
		RunAtLoad        bool     `plist:"RunAtLoad"`

		StandardOutPath   string `plist:"StandardOutPath"`
		StandardErrorPath string `plist:"StandardErrorPath"`
	}
	data := &serviceHeader{
		Label:             "no.watn.magnus.scproxy",
		ProgramArguments:  []string{executable},
		KeepAlive:         true,
		RunAtLoad:         true,
		StandardOutPath:   filepath.Join(logsFolder, "scproxy.log"),
		StandardErrorPath: filepath.Join(logsFolder, "scproxy.log"),
	}

	plist, err := plist.MarshalIndent(data, plist.XMLFormat, "\t")
	fatalIfErr(err, "failed to generate plist")

	serviceFolder := filepath.Join(libraryFolder, "LaunchAgents")
	serviceFile := filepath.Join(serviceFolder, "no.watn.magnus.scproxy.plist")

	err = os.WriteFile(serviceFile, plist, 0644)
	fatalIfErr(err, "failed to write plist")

	user, err := user.Current()
	fatalIfErr(err, "failed to get current user")

	// We need to enable it, in case it has been disabled before.
	err = exec.Command("launchctl", "enable", fmt.Sprintf("gui/%s/no.watn.magnus.scproxy", user.Uid)).Run()
	fatalIfErr(err, "failed to enable service")

	err = exec.Command("launchctl", "bootstrap", fmt.Sprintf("gui/%s", user.Uid), serviceFile).Run()
	fatalIfErr(err, "failed to bootstrap service")
}

func uninstallServiceOnDarwin() {
	libraryFolder := filepath.Join(os.Getenv("HOME"), "Library")
	serviceFolder := filepath.Join(libraryFolder, "LaunchAgents")
	serviceFile := filepath.Join(serviceFolder, "no.watn.magnus.scproxy.plist")
	if !fileExists(serviceFile) {
		log.Printf("Service not installed")
		return
	}
	err := os.Remove(serviceFile)
	fatalIfErr(err, "failed to remove plist")

	user, err := user.Current()
	fatalIfErr(err, "failed to get current user")

	err = exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%s/no.watn.magnus.scproxy", user.Uid)).Run()
	fatalIfErr(err, "failed to bootout service")
}

func generateTlsCert() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fatalIfErr(err, "failed to generate the CA key")
	pub := priv.Public()

	spkiASN1, err := x509.MarshalPKIXPublicKey(pub)
	fatalIfErr(err, "failed to encode public key")

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}

	_, err = asn1.Unmarshal(spkiASN1, &spki)
	fatalIfErr(err, "failed to decode public key")

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")

	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "scproxy",
		},
		SubjectKeyId: skid[:],

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		KeyUsage: x509.KeyUsageDigitalSignature,

		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	fatalIfErr(err, "failed to generate CA certificate")

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	fatalIfErr(err, "failed to encode CA key")

	certPath, KeyPath := getCertAndKeyPath()

	err = os.WriteFile(KeyPath, pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0400)
	fatalIfErr(err, "failed to save CA key")

	err = os.WriteFile(certPath, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	fatalIfErr(err, "failed to save CA certificate")
}

func getCertAndKeyPathAndValidate() (string, string, error) {

	certPath, keyPath := getCertAndKeyPath()

	_, err1 := os.Stat(certPath)
	_, err2 := os.Stat(keyPath)

	if err1 != nil {
		return certPath, keyPath, err1
	}

	if err2 != nil {
		return certPath, keyPath, err2
	}

	return certPath, keyPath, nil
}

func install(skipService bool) {

	certFolder := getCertFolder()
	err := os.MkdirAll(certFolder, 0700)
	fatalIfErr(err, "failed to create certificate folder")

	_, err = os.Stat(filepath.Join(certFolder, "cert.pem"))
	if err == nil {
		log.Fatalf("Seems like installation has already been done. Skipping")
	}

	log.Printf("Generating new TLS certificate")
	generateTlsCert()
	_, err = os.Stat(filepath.Join(certFolder, "cert.pem"))
	fatalIfErr(err, "failed to generate the certificate")

	log.Printf("Installing certificate into local trust store")
	err = truststore.InstallFile(filepath.Join(certFolder, "cert.pem"))
	fatalIfErr(err, "failed to install the certificate into the local trust store")

	if !(skipService) {
		log.Printf("Installing service")
		switch {
		case runtime.GOOS == "darwin":
			installServiceOnDarwin()
		case runtime.GOOS == "linux":
			installServiceOnLinux()
		default:
			log.Printf("WARN: Service must be installed manually on this OS")
		}
	}

	log.Printf("Installation complete")
}

func uninstall() {

	if runtime.GOOS == "darwin" {
		uninstallServiceOnDarwin()
	} else if runtime.GOOS == "linux" {
		uninstallServiceOnLinux()
	}

	certPath, _ := getCertAndKeyPath()

	if fileExists(certPath) {
		log.Printf("Uninstalling certificate from local trust store")
		err := truststore.UninstallFile(certPath)
		if err != nil {
			log.Printf("WARN: failed to uninstall certificate. Must be done manually: %s", err)
		}
	}

	log.Printf("Removing certificate folder")
	certFolder := getCertFolder()
	err := os.RemoveAll(certFolder)
	fatalIfErr(err, "failed to remove certificate folder")

	log.Printf("Uninstallation complete")
}
