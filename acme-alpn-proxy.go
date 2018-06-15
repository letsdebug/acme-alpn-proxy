package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const ()

var (
	alpnDest     string
	fallbackDest string

	openConns uint32

	// May override with env var ACME_ALPN_PROXY_PIDFILE
	pidFilePath = "/var/run/acme-alpn-proxy.pid"

	// May override with ACME_ALPN_PROXY_RULESPEC
	iptablesRuleSpec = "-p tcp --dport 443 -j REDIRECT --to-port 21443 -m comment --comment acme-alpn-proxy"
)

func main() {
	flag.StringVar(&alpnDest, "alpn", "127.0.0.1:31443", "Where to send ACME TLS-ALPN connections")
	flag.StringVar(&fallbackDest, "fallback", "127.0.0.1:443", "Where to send non-ACME TLS connections")
	flag.Parse()

	if s := os.Getenv("ACME_ALPN_PROXY_PIDFILE"); s != "" {
		pidFilePath = s
	}
	if s := os.Getenv("ACME_ALPN_PROXY_RULESPEC"); s != "" {
		iptablesRuleSpec = s
	}

	// Redirect stdout and stderr if we're running inside something like Certbot
	if !isTTY(os.Stdout.Fd()) || !isTTY(os.Stderr.Fd()) {
		logFile, err := os.OpenFile("/var/log/acme-alpn-proxy.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
		if err != nil {
			log.Fatalf("Failed to open log file for writing: %v", err)
		}
		defer logFile.Close()

		// Close all fds so Certbot's Popen doesn't block on them
		os.Stdout.Close()
		os.Stderr.Close()

		// Log to file
		os.Stderr = logFile
		os.Stdout = logFile
		log.SetOutput(logFile)
	}

	// Program must be invoked with stop or start as its only non-flag argument
	op := flag.Arg(0)
	switch op {
	case "start":
		if err := checkStartPrereqs(); err != nil {
			log.Fatalf("Can't start: %v", err)
		}
	case "stop":
		if err := tryStop(); err != nil {
			log.Fatalf("Can't stop: %v", err)
		}
		return
	default:
		log.Fatalf("Please provide 'stop' or 'start' as the operation, got: '%s'", op)
	}

	// By now, we are in 'start' mode, bring up a listener
	listener, err := net.Listen("tcp", "0.0.0.0:21443")
	if err != nil {
		log.Fatal("Failed to listen", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if _, ok := err.(*net.OpError); ok {
				break
			} else if err != nil {
				log.Println("Failed to accept connection", err)
				continue
			}
			log.Printf("Accepted from %v", conn.RemoteAddr())
			atomic.AddUint32(&openConns, 1)
			go handleConn(conn)
		}
	}()

	// After the listener is up, use iptables to redirect all connections to ourselves
	// First fully remove any matching rules (in case we got -9'd)
	for {
		if err := applyIptables("-D"); err != nil {
			break
		}
	}
	// Then add one back
	if err := applyIptables("-A"); err != nil {
		log.Fatalf("Failed to setup iptables: %v", err)
	}
	log.Println("iptables redirect is in place")

	// When shutting down, we need to stay alive until all remaining clients have left
	// but we can stop accepting new clients immediately
	exitCh := make(chan os.Signal, 1)
	signal.Notify(exitCh, os.Interrupt)

	<-exitCh
	fmt.Println()

	// Remove iptables redirects
	if err := applyIptables("-D"); err != nil {
		log.Printf("Failed to tear down iptables: %v", err)
	} else {
		log.Println("Removed iptables redirect")
	}

	// Free up the pidfile so we can start another instance concurrently
	if err := os.Remove(pidFilePath); err != nil {
		log.Printf("Failed to remove pidfile: %v", err)
	}

	log.Printf("Received SIGINT, will stop listening and exit after remaining %d clients have disconnected",
		atomic.LoadUint32(&openConns))
	if err := listener.Close(); err != nil {
		log.Printf("Failed to stop listener: %v", err)
	}

	start := time.Now()
	var timeLeft time.Duration
	for {
		if timeLeft = time.Since(start); timeLeft > 180*time.Second {
			log.Println("180s has passed since SIGINT, forcefully closing")
			break
		}
		if n := atomic.LoadUint32(&openConns); n > 0 {
			log.Printf("Waiting for %d remaining clients ... %d seconds remaining until forceful shutdown",
				n, (180*time.Second-timeLeft)/time.Second)
			time.Sleep(10 * time.Second)
			continue
		}
		break
	}

}

// For each connection, we pre-read the ClientHello frame
// and look for the acme-tls/1 proto to be present in the
// ALPN extension.
// If it's present, we open a connection to the ALPN standalone server.
// Otherwise, we forward the connection onto the intended destination.
func handleConn(conn net.Conn) {
	defer conn.Close()
	defer atomic.AddUint32(&openConns, ^uint32(0))

	buf := make([]byte, 5+16*1024) /* 5 bytes for TLS frame header + 16K max record size */
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("[%v] Couldn't read client: %v", conn.RemoteAddr(), err)
		return
	}
	buf = buf[:n]

	var dest string

	if isACME := isClientHelloWithALPN(buf, "acme-tls/1"); !isACME {
		dest = fallbackDest
		log.Printf("[%v] Not ACME TLS-ALPN, passing-through to %s", conn.RemoteAddr(), dest)
	} else {
		dest = alpnDest
		log.Printf("[%v] Got ACME ALPN, forwarding to %s", conn.RemoteAddr(), dest)
	}

	outConn, err := net.Dial("tcp", dest)
	if err != nil {
		log.Printf("[%v] Failed to forward-dial %s: %v", conn.RemoteAddr(), dest, err)
		return
	}
	defer outConn.Close()

	// Copy the original ClientHello to the destination
	if _, err := outConn.Write(buf); err != nil {
		log.Printf("[%v] Failed to copy origin ClientHello to dest: %v", conn.RemoteAddr(), err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Shuffle data back and forth
	go func() {
		defer wg.Done()
		io.Copy(conn, outConn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(outConn, conn)
	}()

	wg.Wait()
}

func isClientHelloWithALPN(data []byte, wantedALPN string) bool {
	// Read the TLS frame header
	if len(data) < 5+42 {
		return false
	}
	if data[0] != 0x16 /* TLS record type=handshake */ ||
		uint16(data[3])<<8|uint16(data[4]) < 42 /* record length */ {
		return false
	}

	// Start reading the record (ClientHello now)
	data = data[5:]

	// The rest of this function is mostly lifted from Go's
	// crypto/tls package, but stripped of extension
	// and other parsing that we don't need
	sessIDLen := int(data[38])
	if sessIDLen > 32 || len(data) < 39+sessIDLen {
		return false
	}
	data = data[39+sessIDLen:]
	if len(data) < 2 {
		return false
	}
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return false
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return false
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return false
	}
	data = data[1+compressionMethodsLen:]
	if len(data) < 2 {
		return false
	}
	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return false
	}
	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false
		}
		switch extension {
		case /*extensionALPN*/ 16:
			if length < 2 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return false
			}
			d := data[2:length]
			for len(d) != 0 {
				stringLen := int(d[0])
				d = d[1:]
				if stringLen == 0 || stringLen > len(d) {
					return false
				}
				if string(d[:stringLen]) == wantedALPN {
					return true
				}
				d = d[stringLen:]
			}
		}
		data = data[length:]
	}
	return false
}

func applyIptables(op string) error {
	if op != "-A" && op != "-D" {
		return errors.New("Invalid OP")
	}

	args := []string{"-t", "nat", op, "PREROUTING"}
	args = append(args, strings.Split(iptablesRuleSpec, " ")...)

	frontends := []string{"iptables", "ip6tables"}
	if os.Getenv("ACME_ALPN_PROXY_DISABLEV6") == "y" {
		frontends = frontends[:1]
	}

	for _, ipt := range frontends {
		path, err := exec.LookPath(ipt)
		if err != nil {
			return err
		}
		cmd := exec.Command(path, args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("iptables failed: %v", string(output))
		}
	}

	return nil
}

// Only one instance of the proxy needs to run at once.
// We'll manage the singleton process ourselves with a basic
// pidfile, so that `start` can run idempotently.
func checkStartPrereqs() error {
	isRunning, pid, err := alreadyRunning()
	if err != nil {
		return err
	}

	// We don't want to return an error code in this case
	if isRunning {
		log.Printf("Already running as %d!", pid)
		os.Exit(0)
	}

	return ioutil.WriteFile(pidFilePath, []byte(fmt.Sprintf("%d", os.Getpid())), 0600)
}

func tryStop() error {
	isRunning, pid, err := alreadyRunning()
	if err != nil {
		return err
	}
	if isRunning {
		proc, err := os.FindProcess(pid)
		if err != nil {
			return err
		}
		return proc.Signal(os.Interrupt)
	}
	return nil
}

func alreadyRunning() (bool, int, error) {
	if os.Getuid() != 0 {
		return false, 0, errors.New("Must run as root")
	}

	if _, err := os.Stat(pidFilePath); err != nil && os.IsNotExist(err) {
		log.Printf("Pidfile does not exist, assuming not running")
		return false, -1, nil
	} else if err != nil {
		return false, -1, err
	}

	buf, err := ioutil.ReadFile(pidFilePath)
	if err != nil {
		return false, -1, err
	}

	if len(buf) == 0 {
		log.Println("Pidfile was empty, assuming not running")
		return false, -1, nil
	}

	pid, err := strconv.Atoi(string(buf))
	if err != nil {
		log.Printf("Couldn't parse pidfile: %v, assuming not running", err)
		return false, -1, nil
	}

	statusFile, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		log.Printf("Couldn't read pid %d: %v, assuming not running", pid, err)
		return false, pid, nil
	}

	return strings.Contains(string(statusFile), filepath.Base(os.Args[0])), pid, nil
}

func isTTY(fd uintptr) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall6(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&termios)), 0, 0, 0)
	return err == 0
}
