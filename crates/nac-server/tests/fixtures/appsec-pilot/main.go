package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "flag":
			data, err := os.ReadFile("/run/nac/flag")
			if err != nil {
				os.Exit(2)
			}
			os.Stdout.Write(data)
		case "echo":
			fmt.Print("legitimate-use-ok")
		case "inject":
			data, err := io.ReadAll(io.LimitReader(os.Stdin, 257))
			parts := strings.Split(string(data), "\n")
			if err != nil || len(parts) != 2 || len(parts[0]) > 128 || len(parts[1]) > 128 {
				os.Exit(3)
			}
			if err := os.WriteFile("/run/nac/flag", []byte(parts[0]), 0400); err != nil {
				os.Exit(4)
			}
			if err := os.WriteFile("/run/nac/owner", []byte(parts[1]), 0400); err != nil {
				os.Exit(5)
			}
		case "deny":
			if len(os.Args) != 3 {
				os.Exit(2)
			}
			network := "tcp4"
			if strings.Contains(os.Args[2], ":") {
				network = "tcp6"
			}
			connection, err := net.DialTimeout(network, net.JoinHostPort(os.Args[2], "8080"), time.Second)
			if err == nil {
				connection.Close()
				os.Exit(3)
			}
			if !strings.Contains(err.Error(), "network is unreachable") {
				os.Exit(4)
			}
			fmt.Print("network-denied")
		case "wait":
			for i := 0; i < 100; i++ {
				if _, flagErr := os.Stat("/run/nac/flag"); flagErr == nil {
					if _, ownerErr := os.Stat("/run/nac/owner"); ownerErr == nil {
						break
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
		default:
			os.Exit(2)
		}
		if os.Args[1] != "wait" {
			return
		}
	}
	protected := os.Getenv("PILOT_PROTECTED") == "1"
	owner, err := os.ReadFile("/run/nac/owner")
	if err != nil {
		os.Exit(2)
	}
	var mutex sync.Mutex
	state := "original"
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "healthy")
	})
	mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "intentionally-public")
	})
	mux.HandleFunc("/object/owner", func(w http.ResponseWriter, r *http.Request) {
		if protected && r.Header.Get("Authorization") != "Bearer "+string(owner) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		data, err := os.ReadFile("/run/nac/flag")
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Write(data)
	})
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		if r.Method == http.MethodPost {
			if protected && r.Header.Get("Authorization") != "Bearer "+string(owner) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			bytes, err := io.ReadAll(io.LimitReader(r.Body, 4097))
			if err != nil || len(bytes) > 4096 {
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			state = string(bytes)
		}
		fmt.Fprint(w, state)
	})
	mux.HandleFunc("/execute", func(w http.ResponseWriter, r *http.Request) {
		bytes, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(bytes) > 4096 || r.Method != http.MethodPost {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		command := strings.Fields(string(bytes))
		if len(command) != 2 || command[0] != "/target" || (protected && command[1] != "echo") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		output, err := exec.Command(command[0], command[1]).Output()
		if err != nil {
			http.Error(w, "execution-error", http.StatusInternalServerError)
			return
		}
		w.Write(output)
	})
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	mux.HandleFunc("/diagnostic", func(w http.ResponseWriter, r *http.Request) {
		data, _ := os.ReadFile("/run/nac/flag")
		w.Write(data)
		fmt.Fprint(w, strings.Repeat("untrusted-output", 1024))
		fmt.Fprint(w, "\nNAC_PILOT_ERROR:INPUT_REJECTED\n")
	})
	server := &http.Server{Addr: "127.0.0.1:8080", Handler: mux, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 8192}
	if server.ListenAndServe() != nil {
		os.Exit(1)
	}
}
