 

## Báo cáo hoàn thành hệ thống Validating Webhook “Verify Image” (Kubernetes)

### 1) Thông tin chung
- **Tên đề tài:** Xây dựng hệ thống kiểm soát/kiểm chứng image container trước khi tạo Pod bằng **Validating Admission Webhook**.
- **Repository:** `image-policy-operator`
- **Ngôn ngữ/Công nghệ:** Go (Kubebuilder / controller-runtime), Kubernetes Admission Webhook, CRD, Kustomize, (tùy chọn) cert-manager, Cosign (sigstore), Telegram Bot API (thông báo).

---

### 2) Mục tiêu hệ thống
Hệ thống có mục tiêu **ngăn (hoặc ghi nhận) việc chạy Pod sử dụng image không đạt yêu cầu**, cụ thể là:
- Chặn tạo Pod nếu image **không có chữ ký (signature) hợp lệ** theo Cosign (khi policy ở chế độ **Enforce**).
- Cho phép tạo Pod nhưng vẫn ghi nhận/thông báo nếu policy ở chế độ **Audit**.
- Cho phép quản trị viên định nghĩa phạm vi policy bằng tài nguyên tùy biến **`ClusterImagePolicy`** (CRD).

---

### 3) Kiến trúc & thành phần đã triển khai

#### 3.1 CRD `ClusterImagePolicy`
Em đã định nghĩa CRD cluster-scope để mô tả chính sách:
- File định nghĩa API: clusterimagepolicy_types.go
- CRD generate: security.shieldx-bot.io_clusterimagepolicies.yaml

**Các trường quan trọng trong spec:**
- `action`: `"Enforce"` hoặc `"Audit"`
- `images[]`: danh sách rule theo `glob` để match image
- `publicKeys[]`: tham chiếu Secret (hiện tại CRD có nhưng phần webhook đang dùng key từ env/secret chung, chưa đọc theo từng policy)
- `namespaces[]` (optional): giới hạn namespace áp dụng
- `priority` (optional): ưu tiên (hiện tại webhook chưa dùng để sắp xếp)

Có mẫu policy: security_v1_clusterimagepolicy.yaml.

#### 3.2 Validating Webhook cho Pod
Webhook được đăng ký để validate Pod khi **CREATE/UPDATE**:
- Annotation Kubebuilder trong code: pod_webhook.go
- Manifest webhook: manifests.yaml
- Service cho webhook: service.yaml

**Thông số chính:**
- Path: `/validate--v1-pod`
- `failurePolicy: Fail` ⇒ nếu webhook lỗi/không reachable thì API Server sẽ **từ chối** (an toàn theo hướng “deny by default”).

#### 3.3 TLS cho webhook (cert-manager) + mount cert vào manager
Hệ thống dùng cert-manager để cấp chứng chỉ TLS cho webhook service:
- Certificate: certificate-webhook.yaml
- Issuer: issuer.yaml
- Patch mount cert vào pod manager: manager_webhook_patch.yaml
- Kustomize tổng: kustomization.yaml (deploy vào namespace `image-policy-operator-system` với `namePrefix: image-policy-operator-`)

#### 3.4 Controller Manager entrypoint
Chương trình chính: main.go
- Có cơ chế **tự tắt webhook khi chạy local** nếu thiếu cert ở `/tmp/k8s-webhook-server/serving-certs` (tránh crash khi dev).
- Mặc định **disable HTTP/2** để né các CVE liên quan.
- Khởi tạo controller cho CRD `ClusterImagePolicy` (hiện `Reconcile` đang để TODO).
- Đăng ký webhook Pod khi webhooks bật.

---

### 4) Luồng xử lý kiểm tra image (chi tiết logic)
File trọng tâm: pod_webhook.go

#### 4.1 Khi tạo Pod (ValidateCreate)
- Webhook nhận Pod object.
- Duyệt từng container trong `pod.Spec.Containers`:
  1) Lấy `container.Image` và `pod.Namespace`.
  2) Gọi `GetListClusterImagePolicy(image, namespace)` để xem policy có cho phép hay không.
  3) Nếu **không hợp lệ** ⇒ trả lỗi `image ... is not allowed...` ⇒ Kubernetes **từ chối tạo Pod**.

#### 4.2 Cách hệ thống tìm policy áp dụng
Hàm `GetListClusterImagePolicy`:
- Tạo dynamic client và **List toàn bộ** `clusterimagepolicies.security.shieldx-bot.io/v1`.
- Với mỗi policy:
  - Kiểm tra `spec.namespaces` có chứa namespace Pod hay không.
  - Duyệt `spec.images[].glob` để match với image.
  - Nếu `action == "Enforce"`:
    - Nếu glob match ⇒ chạy `VerifyImageSignature(image)` bằng Cosign:
      - Pass ⇒ cho phép
      - Fail ⇒ ghi log + gửi Telegram + **deny**
  - Nếu `action != "Enforce"` (tức Audit):
    - Cho phép (hiện code cho phép và có gửi Telegram)

#### 4.3 Match glob image (đã xử lý normalize)
Các hàm hỗ trợ:
- `normalizeImage`: thêm prefix `docker.io/library/` khi image không có `/`, thêm `:latest` nếu thiếu tag/digest.
- `stripTagOrDigest`: loại bỏ tag/digest để match theo “repo”.
- `matchImageGlob`: dùng `filepath.Match()` để match theo glob.

=> Mục tiêu là policy có thể viết kiểu `docker.io/library/nginx` hoặc wildcard theo repo.

#### 4.4 Xác minh chữ ký Cosign
Hàm `VerifyImageSignature`:
- Parse image reference.
- Load public key bằng `LoadCosignVerifier` theo ưu tiên:
  1) `COSIGN_PUB_KEY_PEM` (PEM content)
  2) `COSIGN_PUB_KEY` (đường dẫn file)
  3) fallback file repo-local `internal/webhook/v1/PushkeyCluster/cosign.pub` (nếu có)
  4) fallback `$HOME/cosign.pub`
- Dùng `cosign.VerifyImageSignatures`.
- Với Rekor/tlog:
  - Nếu load Rekor pubs fail:
    - Nếu `COSIGN_IGNORE_TLOG=true` ⇒ bỏ qua tlog verify (đã được set trong manager.yaml để tránh lỗi ghi vào `$HOME/.sigstore` khi filesystem read-only)
    - Ngược lại ⇒ trả lỗi.

---

### 5) Thông báo Telegram (giám sát/ghi nhận)
Hàm `sendTelegramMessage` gửi tin nhắn nếu có:
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

Tài liệu cấu hình: environment-variables.md  
Manifest manager.yaml inject env từ Secret:
- `telegram-credentials` (keys `botToken`, `chatId`)
- `cosign-pub-key` (key `cosign.pub`) cho `COSIGN_PUB_KEY_PEM`

Nếu thiếu secret/env ⇒ tính năng Telegram tự tắt (không làm webhook crash).

---

### 6) Kết quả đạt được
Sau khi hoàn thiện, hệ thống đã có các khả năng chính:
- Có CRD `ClusterImagePolicy` để khai báo chính sách ở mức cluster.
- Có Validating Webhook chặn/cho phép Pod dựa trên policy.
- Có kiểm tra chữ ký Cosign cho image khi policy ở **Enforce**.
- Có cơ chế thông báo Telegram khi image không đạt (và một số tình huống khác).
- Có cấu hình triển khai bằng Kustomize + cert-manager để chạy trong cluster với TLS chuẩn.

---

### 7) Công cụ hỗ trợ debug (em đã chuẩn bị)
Có chương trình debug liệt kê policy trong cluster:
- main.go

Giúp kiểm tra nhanh cluster đã có CRD/policy hay chưa.

---

### 8) Hạn chế hiện tại & hướng phát triển
Các điểm em ghi nhận còn có thể cải thiện thêm:
1) **Controller reconcile cho `ClusterImagePolicy` hiện để TODO** (clusterimagepolicy_controller.go). Hiện enforcement chủ yếu nằm ở webhook (đọc policy trực tiếp qua dynamic client).
2) Trường `spec.publicKeys[].secretRef` trong CRD **đã có**, nhưng webhook **chưa đọc key theo từng policy** (đang dùng `COSIGN_PUB_KEY_PEM`/file global).
3) `ValidateUpdate`/`ValidateDelete` của Pod webhook hiện chưa có logic enforcement (Update mới chỉ log).
4) Logic match namespace đang dùng `strings.Contains(fmt.Sprintf("%v", ...), namespace)` ⇒ về sau nên đổi sang so sánh phần tử rõ ràng để tránh match sai.

---

## Checklist tóm tắt (để gửi giáo viên)
- [x] Tạo CRD `ClusterImagePolicy` (Enforce/Audit, images glob, namespaces, publicKeys ref).
- [x] Tích hợp Validating Webhook cho Pod (`/validate--v1-pod`, failurePolicy Fail).
- [x] Cài đặt verify chữ ký image bằng Cosign (có cơ chế bỏ qua tlog khi cần).
- [x] Tích hợp thông báo Telegram qua env/Secret (không hard-code).
- [x] Triển khai manifests với Kustomize + cert-manager + mount TLS cert cho webhook.

---
 