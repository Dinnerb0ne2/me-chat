# me-chat

纯 Python 标准库实现的加密聊天示例，包含：
- TLS 保护的 `server`
- 端到端（应用层）加密 `client`
- 客户端可选 `CLI` 或 `WebUI`

> 运行环境：Python 3.14.3（纯标准库，无第三方依赖）

## 安全模型

- **传输层加密**：Client ↔ Server 使用 TLS 1.3（`ssl`）
- **应用层端到端加密**：
  - 客户端使用房间口令派生密钥（`hashlib.scrypt`）
  - 消息使用基于 HMAC-SHA256 的流式加密 + Encrypt-then-MAC 认证
  - 服务器仅转发密文，无法解密消息内容

## 快速开始

### 1) 生成 TLS 证书（示例）

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout server.key -out server.crt -subj "/CN=localhost"
```

### 2) 创建用户

```bash
python -m me_chat.server create-user \
  --users users.json \
  --username alice \
  --password 'your-server-password'
```

### 3) 启动服务端

```bash
python -m me_chat.server serve \
  --host 0.0.0.0 \
  --port 7443 \
  --certfile server.crt \
  --keyfile server.key \
  --users users.json
```

### 4) 启动客户端（CLI）

```bash
python -m me_chat.client \
  --host localhost \
  --port 7443 \
  --cafile server.crt \
  --username alice \
  --room prod-room \
  --ui cli
```

然后输入：
- `Server password`：服务端账户密码
- `Room passphrase (E2E)`：房间端到端口令（仅客户端知道）

### 5) 启动客户端（WebUI，可选）

```bash
python -m me_chat.client \
  --host localhost \
  --port 7443 \
  --cafile server.crt \
  --username alice \
  --room prod-room \
  --ui web \
  --web-host 127.0.0.1 \
  --web-port 8765
```

会自动打开本地浏览器页面（仅本地监听）。

## 生产部署建议

- 使用受信任 CA 证书，严格启用证书校验（不要使用 `--insecure`）
- 为每个房间使用高强度随机口令，并通过安全信道分发
- 服务端运行在最小权限账户，配合防火墙与审计日志
- 定期轮换用户密码与房间口令
- 用进程守护（systemd/supervisor）管理服务可用性

## 限制与说明

- 该实现坚持“纯标准库”约束，应用层加密采用可审计的 HMAC 派生流方案
- 如需更强的现代 AEAD/前向保密特性，建议在允许第三方依赖时迁移到专业密码学库

## 测试

```bash
python -m unittest discover -v
```
