/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	"context"

	"crypto"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cosignsignature "github.com/sigstore/cosign/v2/pkg/signature"
	sigstoresignature "github.com/sigstore/sigstore/pkg/signature"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func GetClientset() (*kubernetes.Clientset, *rest.Config, error) {
	// Prefer in-cluster config (webhook runs inside Kubernetes).
	if cfg, err := rest.InClusterConfig(); err == nil {
		clientset, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create in-cluster clientset: %w", err)
		}
		return clientset, cfg, nil
	}

	// Fallback for local development: use kubeconfig.
	var kubeconfig *string
	home := homedir.HomeDir()
	if home != "" {
		defaultPath := filepath.Join(home, ".kube", "config")
		if kc := os.Getenv("KUBECONFIG"); kc != "" {
			defaultPath = kc
		}
		kubeconfig = flag.String("kubeconfig", defaultPath, "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute ")
	}
	if !flag.Parsed() {
		flag.Parse()
	}
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("không tìm thấy file kubeconfig: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("token/config không đúng: %w", err)
	}

	return clientset, config, nil
}

type ClusterImagePolicy struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Metadata   map[string]interface{} `json:"metadata"`
	Spec       map[string]interface{} `json:"spec"`
	Uid        interface{}            `json:"uid"`
}

func LoadCosignVerifier(ctx context.Context) (sigstoresignature.Verifier, error) {
	// For debug use-cases we support either:
	// - COSIGN_PUB_KEY_PEM: the PEM content
	// - COSIGN_PUB_KEY:     filesystem path to the key (default: $HOME/cosign.pub)
	if pubKeyPEM := os.Getenv("COSIGN_PUB_KEY_PEM"); pubKeyPEM != "" {
		// LoadPublicKeyRaw expects PEM bytes + hash algorithm.
		return cosignsignature.LoadPublicKeyRaw([]byte(pubKeyPEM), crypto.SHA256)
	}

	// Prefer an explicit path.
	if keyRef := strings.TrimSpace(os.Getenv("COSIGN_PUB_KEY")); keyRef != "" {
		return cosignsignature.LoadPublicKey(ctx, keyRef)
	}

	// Convenience for this repository's debug utility: if the repo-local key exists,
	// use it automatically when COSIGN_PUB_KEY is not set.
	// This assumes you run from the repo root.
	repoLocalKey := filepath.Join("internal", "webhook", "v1", "PushkeyCluster", "cosign.pub")
	if _, err := os.Stat(repoLocalKey); err == nil {
		return cosignsignature.LoadPublicKey(ctx, repoLocalKey)
	}

	// Fallback to $HOME/cosign.pub
	pubKeyPath := filepath.Join(os.Getenv("HOME"), "cosign.pub")
	if strings.TrimSpace(pubKeyPath) == "" {
		return nil, fmt.Errorf("COSIGN_PUB_KEY is empty and HOME is not set")
	}
	return cosignsignature.LoadPublicKey(ctx, pubKeyPath)

}
func sendTelegramMessage(ctx context.Context, msg string) {
	telegramToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	telegramChatID := os.Getenv("TELEGRAM_CHAT_ID")
	if telegramToken == "" || telegramChatID == "" {
		fmt.Printf("Telegram notification disabled (missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID)")
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", telegramToken)
	form := url.Values{}
	form.Set("chat_id", telegramChatID)
	form.Set("text", msg)
	// Intentionally do not set parse_mode here.
	// Telegram's Markdown parser is strict and can reject messages containing characters
	// like []()<>. Plain text is safer for debug output.

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		fmt.Printf("failed to build Telegram request: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("failed to send Telegram notification: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		fmt.Printf("Telegram API returned non-2xx: status=%s body=%s\n", resp.Status, string(body))
	}
}

func VerifyImageSignature(image string) error {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	img := strings.TrimSpace(image)
	if img == "" {
		return fmt.Errorf("empty image")
	}

	if strings.HasSuffix(img, ".sig") && strings.Contains(img, ":sha256-") {
		return fmt.Errorf("image looks like a cosign signature artifact tag (ends with .sig); verify the real image tag/digest instead, e.g. repo:tag or repo@sha256:...")
	}
	ref, err := name.ParseReference(img)
	if err != nil {
		return err
	}

	verifier, err := LoadCosignVerifier(ctx)
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}

	co := &cosign.CheckOpts{SigVerifier: verifier}

	if rekorPubs, e := cosign.GetRekorPubs(ctx); e == nil {
		co.RekorPubKeys = rekorPubs
	} else {
		if getenv("COSIGN_IGNORE_TLOG", "false") == "true" {
			co.IgnoreTlog = true
			log.Printf("warning: cannot load Rekor public keys (%v); COSIGN_IGNORE_TLOG=true so skipping tlog verification", e)
		} else {
			return fmt.Errorf("cannot load Rekor public keys (needed to verify bundle): %w (set COSIGN_IGNORE_TLOG=true to skip tlog verification)", e)
		}
	}

	_, _, err = cosign.VerifyImageSignatures(ctx, ref, co)
	if err != nil {
		return fmt.Errorf("verify failed for %q: %w", img, err)
	}
	return nil

}

func normalizeImage(img string) string {
	img = strings.TrimSpace(img)

	if !strings.Contains(img, "/") {
		img = "docker.io/library/" + img
	}

	if !strings.Contains(img, ":") && !strings.Contains(img, "@") {
		img = img + ":latest"
	}

	return img
}

// Strip tag or digest (repo-only)
// docker.io/a/b:c   -> docker.io/a/b
// docker.io/a/b@sha -> docker.io/a/b
func stripTagOrDigest(img string) string {
	if strings.Contains(img, "@") {
		return strings.Split(img, "@")[0]
	}
	if strings.Count(img, ":") > 1 {
		// registry:port/image:tag
		return img
	}
	if strings.Contains(img, ":") {
		return strings.Split(img, ":")[0]
	}
	return img
}

// FIXED matcher
func matchImageGlob(glob, image string) bool {
	glob = normalizeImage(glob)
	image = normalizeImage(image)

	// 👉 match theo repo
	globRepo := stripTagOrDigest(glob)
	imageRepo := stripTagOrDigest(image)

	ok, err := filepath.Match(globRepo, imageRepo)
	if err != nil {
		return false
	}
	return ok
}

func GetListClusterImagePolicy(image string, namespace string) bool {
	_, cfg, err := GetClientset()
	if err != nil {
		fmt.Println("Lỗi:", err)
		return false
	}

	gvr := schema.GroupVersionResource{
		Group:    "security.shieldx-bot.io",
		Version:  "v1",
		Resource: "clusterimagepolicies",
	}
	dynamicClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		fmt.Println("Lỗi tạo dynamic client:", err)
		return false
	}

	list, err := dynamicClient.Resource(gvr).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		fmt.Println("Lỗi lấy danh sách ClusterImagePolicy:", err)
		return false
	}
	fmt.Printf("ClusterImagePolicy: %d item(s)\n", len(list.Items))
	var checkGlob bool = false
	for i := range list.Items {
		item := list.Items[i]

		for _, img := range item.Object["spec"].(map[string]interface{})["images"].([]interface{}) {

			imageMap := img.(map[string]interface{})
			glob := imageMap["glob"].(string)
			check := item.Object["spec"].(map[string]interface{})["namespaces"]
			if strings.Contains(fmt.Sprintf("%v", check), namespace) {
				if item.Object["spec"].(map[string]interface{})["action"] == "Enforce" {
					if matchImageGlob(glob, image) {

						if err := VerifyImageSignature(image); err != nil {
							fmt.Printf(
								"Image %s không hợp lệ theo ClusterImagePolicy %s (action: %s)\nReason: %v\n",
								image,
								item.GetName(),
								item.Object["spec"].(map[string]interface{})["action"],
								err,
							)
							sendTelegramMessage(
								context.Background(),
								fmt.Sprintf(
									"Image %s không hợp lệ theo ClusterImagePolicy %s (action: %s)\nReason: %v",
									image,
									item.GetName(),
									item.Object["spec"].(map[string]interface{})["action"],
									err,
								),
							)

						} else {
							checkGlob = true
							fmt.Printf("Image %s hợp lệ theo ClusterImagePolicy %s (action: %s)\n", image, item.GetName(), item.Object["spec"].(map[string]interface{})["action"])
						}
						break
					}
				} else {
					sendTelegramMessage(
						context.Background(),
						fmt.Sprintf(
							"Image %s  hợp lệ theo ClusterImagePolicy %s (action: %s)\nReason: %v",
							image,
							item.GetName(),
							item.Object["spec"].(map[string]interface{})["action"],
							err,
						),
					)
					checkGlob = true

				}
			}

		}

	}
	return checkGlob
}

// nolint:unused
// log is for logging in this package.
var podlog = logf.Log.WithName("pod-resource")

// SetupPodWebhookWithManager registers the webhook for Pod in the manager.
func SetupPodWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&corev1.Pod{}).
		WithValidator(&PodCustomValidator{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: If you want to customise the 'path', use the flags '--defaulting-path' or '--validation-path'.
// NOTE: For core resources (apiGroup=""), controller-runtime generates a default path with a double hyphen.
// +kubebuilder:webhook:path=/validate--v1-pod,mutating=false,failurePolicy=fail,sideEffects=None,groups="",resources=pods,verbs=create;update,versions=v1,name=vpod-v1.kb.io,admissionReviewVersions=v1

// PodCustomValidator struct is responsible for validating the Pod resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type PodCustomValidator struct {
	// TODO(user): Add more fields as needed for validation
}

var _ webhook.CustomValidator = &PodCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type Pod.
func (v *PodCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	pod, ok := obj.(*corev1.Pod)

	if !ok {
		return nil, fmt.Errorf("expected a Pod object but got %T", obj)
	}
	for _, container := range pod.Spec.Containers {

		fmt.Printf("Container Name: %s\n", container.Name)
		fmt.Printf("Image: %s\n", container.Image)
		fmt.Printf("Namespace: %s\n", pod.Namespace)
		fmt.Printf("Pod Name: %s\n", pod.Name)
		if GetListClusterImagePolicy(container.Image, pod.Namespace) {
			podlog.Info("Validation for Pod upon creation", "name", pod.GetName())
		} else {
			sendTelegramMessage(
				context.Background(),
				fmt.Sprintf("Image không  hợp lệ theo ClusterImagePolicy , Không tạo pod trong namespace"),
			)
			return nil, fmt.Errorf("image %s is not allowed in namespace %s", container.Image, pod.Namespace)
		}

	}

	// TODO(user): fill in your validation logic upon object creation.
	sendTelegramMessage(
		context.Background(),
		fmt.Sprintf("Image  hợp lệ theo ClusterImagePolicy , Đã tạo pod trong namespace"),
	)
	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type Pod.
func (v *PodCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	pod, ok := newObj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected a Pod object for the newObj but got %T", newObj)
	}
	podlog.Info("Validation for Pod upon update", "name", pod.GetName())

	// TODO(user): fill in your validation logic upon object update.

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type Pod.
func (v *PodCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected a Pod object but got %T", obj)
	}
	podlog.Info("Validation for Pod upon deletion", "name", pod.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil

}
