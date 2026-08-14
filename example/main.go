// Command example shows minimal RudeAuth Go SDK usage.
//
//	go run ./example RUDE-YOUR-LICENCE-KEY
package main

import (
	"fmt"
	"os"

	rudeauth "github.com/Rudevin17/rudeauth-go"
)

// These come from `rudeauth-cli app create`. Both are safe to embed: the public
// key verifies responses, it cannot forge them.
const (
	appID     = "YOUR-APP-UUID"
	publicKey = "YOUR-PUBLIC-KEY-BASE64"
	baseURL   = "https://api.yourproduct.com"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: example <licence-key>")
		os.Exit(2)
	}

	client, err := rudeauth.NewClient(appID, publicKey, baseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "client:", err)
		os.Exit(1)
	}

	sess, err := client.Authenticate(os.Args[1])
	if err != nil {
		// expired is not device-limit is not banned; the error says which.
		fmt.Fprintln(os.Stderr, "authenticate:", err)
		os.Exit(1)
	}
	defer sess.Close()

	fmt.Printf("authenticated: level=%d devices=%d/%d\n",
		sess.Info().Level, sess.Info().DevicesUsed, sess.Info().MaxDevices)

	offset, err := sess.Variable("offset")
	if err != nil {
		fmt.Fprintln(os.Stderr, "variable:", err)
		os.Exit(1)
	}
	fmt.Println("offset:", offset)
}
