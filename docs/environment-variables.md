# Environment variables & Secrets (Telegram)

Tài liệu này mô tả “kĩ thuật biến môi trường” (environment variables) mà project đang dùng để cấu hình Telegram mà **không hard-code** credential trong code.

## 1) Vì sao dùng biến môi trường?

- **Tách cấu hình khỏi code**: cùng một image chạy được ở nhiều cluster/môi trường.
- **Bảo mật**: token/chat id không nằm trong repo, không nằm trong Docker image.
- **Dễ rotate**: đổi Secret và restart Deployment.

Trong project này, webhook/controller sẽ đọc:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`
- `COSIGN_PUB_KEY_PEM` (Cosign public key PEM, dùng để verify signature)

Nếu thiếu (hoặc Secret không tồn tại), Telegram notification sẽ bị tắt (được thiết kế để “optional”).

## 2) Kubernetes: inject biến môi trường từ Secret

File template Deployment nằm ở `config/manager/manager.yaml` và được deploy qua kustomize `config/default`.

Hiện tại, container `manager` lấy env như sau:

- `TELEGRAM_BOT_TOKEN`  
  từ Secret `telegram-credentials`, key `botToken`
- `TELEGRAM_CHAT_ID`  
  từ Secret `telegram-credentials`, key `chatId`

- `COSIGN_PUB_KEY_PEM`  
  từ Secret `cosign-pub-key`, key `cosign.pub` (optional)

> Lưu ý: trong `config/default/kustomization.yaml` có `namespace: image-policy-operator-system`, nên khi deploy, các resource sẽ được đặt vào namespace **image-policy-operator-system** (kể cả `Deployment` và Secret).

### 2.1) Tạo Secret đúng key (khuyến nghị)

Có sẵn file mẫu (placeholder) tại:

- `config/samples/telegram-credentials-secret.yaml`

Bạn thay giá trị thật rồi apply (không commit token thật lên git).

Yêu cầu bắt buộc:

- Secret name: `telegram-credentials`
- Namespace: `image-policy-operator-system`
- Keys: **`botToken`** và **`chatId`** (đúng chính tả, phân biệt hoa thường)

### 2.2) Vì sao `optional: true`?

Trong Deployment, `secretKeyRef.optional: true` nghĩa là:

- Nếu Secret chưa tồn tại: Pod vẫn chạy.
- Nhưng biến môi trường sẽ không có giá trị → tính năng Telegram sẽ tự tắt.

Điều này giúp tránh “crash loop” khi bạn muốn deploy operator trước rồi mới thêm Secret sau.

## 3) Verify nhanh trong cluster

### 3.1) Check Secret tồn tại

- `kubectl -n image-policy-operator-system get secret telegram-credentials`

### 3.2) Check đúng keys

- `kubectl -n image-policy-operator-system get secret telegram-credentials -o jsonpath='{.data}'`

Bạn phải thấy 2 field: `botToken` và `chatId`.

### 3.3) Check env đã được inject vào Pod

- `kubectl -n image-policy-operator-system get pods -l control-plane=controller-manager`

Rồi mô tả pod:

- `kubectl -n image-policy-operator-system describe pod <pod-name>`

Ở phần `Environment:` bạn sẽ thấy 2 biến `TELEGRAM_*` lấy từ Secret.

Và nếu bạn cấu hình Cosign, bạn cũng sẽ thấy `COSIGN_PUB_KEY_PEM` lấy từ Secret `cosign-pub-key`.

> Nếu `COSIGN_PUB_KEY_PEM` không có, webhook sẽ rơi về cơ chế fallback trong code (đọc file `$HOME/cosign.pub`, ví dụ `/home/nonroot/cosign.pub`). Khi file này không tồn tại, verify sẽ báo lỗi kiểu: `open /home/nonroot/cosign.pub: no such file or directory`.

> Tip: `describe` sẽ không in ra value của Secret, chỉ show nguồn tham chiếu (an toàn).

## 4) Local dev (make run) và biến môi trường

Khi chạy local (`make run`), bạn có thể export env trực tiếp:

- `export TELEGRAM_BOT_TOKEN=...`
- `export TELEGRAM_CHAT_ID=...`

Hoặc dùng file `.env` (không commit) và nạp vào shell trước khi chạy.

> Lưu ý: local run có thể gặp lỗi webhook cert nếu bạn bật webhook server nhưng không có cert tại `/tmp/k8s-webhook-server/serving-certs`. Đây là khác biệt giữa chạy trong cluster và local.

## 5) Best practices (để tránh lộ token)

- Không commit token/chatId vào Git.
- Không hard-code trong Go code.
- Tránh log token ra stdout.
- Dùng Secret manager (ExternalSecrets, SealedSecrets, SOPS…) nếu bạn cần quản lý secret theo GitOps.

## 6) Troubleshooting nhanh

- Telegram không gửi:
  - Kiểm tra Secret có tồn tại không và key có đúng `botToken`/`chatId` không.
  - Kiểm tra controller logs.
- Chỉ nhận được header nhưng không có list (ValidatingWebhookConfigurations):
  - Kiểm tra RBAC: manager-role có `list` `validatingwebhookconfigurations`.

