package main

import (
	"context"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1 "github.com/shieldx-bot/image-policy-operator/api/v1"
)

func main() {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	if err := securityv1.AddToScheme(scheme); err != nil {
		fmt.Fprintf(os.Stderr, "failed to add securityv1 scheme: %v\n", err)
		os.Exit(1)
	}

	cfg := ctrl.GetConfigOrDie()

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create controller-runtime client: %v\n", err)
		os.Exit(1)
	}

	var list securityv1.ClusterImagePolicyList
	if err := c.List(ctx, &list); err != nil {
		fmt.Fprintf(os.Stderr, "failed to list ClusterImagePolicy: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("ClusterImagePolicy: %d item(s)\n", len(list.Items))
	for i := range list.Items {
		fmt.Printf("- %s\n", list.Items[i].Name)
	}
}
