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
func healthcheck() {
	req, err := http.NewRequest("HEAD", "http://127.0.0.1:80/", nil)
	if err != nil {
		os.Exit(1)
	}
	_, err = http.DefaultClient.Do(req)
	if err != nil {
		os.Exit(1)
	}
}

func main() {
	var healthcheckFlag = flag.Bool("check-running", false, "check that the proxy is running and healthy")
	flag.Parse()
	if *healthcheckFlag {
		healthcheck()
	}

	target := GetReverseProxyTarget()
	authToken := os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")
	log.Printf("reverse proxying target:%s auth:%s\n", target, authToken)

	handler := handlers.LoggingHandler(os.Stderr,
		addAuthorizationHeader(authToken,
			httputil.NewSingleHostReverseProxy(target)))

	_ = http.ListenAndServe(":80", handler)
}
