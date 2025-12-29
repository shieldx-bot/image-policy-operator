//go:build debug
// +build debug

package main

import (
	"context"
	"fmt"
	"os"

	webhookv1 "github.com/shieldx-bot/image-policy-operator/internal/webhook/v1"
)

func main() {
	// Prints all ValidatingWebhookConfiguration objects visible to the current kubeconfig/in-cluster identity.
	configs, err := webhookv1.GetValidatingWebhookConfiguration(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, c := range configs {
		fmt.Println(c)
	}
}
