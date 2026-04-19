package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/gorilla/handlers"
)

var checkRunningFlag = flag.Bool("check-running", false, "check that the proxy is running and healthy")

func GetReverseProxyTarget() *url.URL {
	url, err := url.Parse(os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"))
	if err != nil {
		log.Fatalln("Bad AWS_CONTAINER_CREDENTIALS_FULL_URI:", err.Error())
	}
	url.Host = "host.docker.internal:" + url.Port()
	return url
}

func addAuthorizationHeader(authToken string, next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Add("Authorization", authToken)
		next.ServeHTTP(w, r)
	}
}

// Send a http request to a running instance on localhost,
// any valid http response is a successful healthcheck
func checkRunning() {
	client := &http.Client{Timeout: 15 * time.Second}

	resp, err := client.Get("http://127.0.0.1/health")
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close()

	os.Exit(0)
}

func main() {
	flag.Parse()
	if *checkRunningFlag {
		checkRunning()

		return
	}

	target := GetReverseProxyTarget()
	authToken := os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")
	log.Printf("reverse proxying target:%s auth:%s\n", target, authToken)

	handler := handlers.LoggingHandler(os.Stderr,
		addAuthorizationHeader(authToken,
			httputil.NewSingleHostReverseProxy(target)))

	_ = http.ListenAndServe(":80", handler)
}
