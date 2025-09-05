# WasmSentinel 部署指南

## Docker 部署

### 1. 构建 Docker 镜像

```dockerfile
FROM golang:1.21-alpine AS builder

# 安装 Rust
RUN apk add --no-cache curl build-base
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup target add wasm32-wasi

WORKDIR /app
COPY . .
RUN ./scripts/build.sh

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/wasm-sentinel .
COPY --from=builder /app/rules ./rules

CMD ["./wasm-sentinel"]
```

### 2. 运行容器

```bash
docker build -t wasm-threat-detector .
docker run -d \
  --name threat-detector \
  --privileged \
  --pid host \
  --network host \
  -v /proc:/host/proc:ro \
  -v /var/log:/var/log \
  wasm-threat-detector
```

## Kubernetes 部署

### 1. DaemonSet 配置

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: wasm-threat-detector
  namespace: security
spec:
  selector:
    matchLabels:
      app: wasm-threat-detector
  template:
    metadata:
      labels:
        app: wasm-threat-detector
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: threat-detector
        image: wasm-threat-detector:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: config
          mountPath: /etc/wasm-threat-detector
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: config
        configMap:
          name: threat-detector-config
```

### 2. ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: threat-detector-config
  namespace: security
data:
  config.yaml: |
    log-level: "info"
    rules: "/etc/rules"
    webhook: "http://alertmanager:9093/api/v1/alerts"
    metrics-port: 8080
```

## 系统服务部署

### 1. Systemd 服务

```ini
[Unit]
Description=WASM Threat Detector
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/wasm-threat-detector --config /etc/wasm-threat-detector/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 2. 安装服务

```bash
sudo cp wasm-threat-detector /usr/local/bin/
sudo mkdir -p /etc/wasm-threat-detector
sudo cp examples/config.yaml /etc/wasm-threat-detector/
sudo cp examples/threat-detector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable threat-detector
sudo systemctl start threat-detector
```

## 云平台部署

### AWS ECS

```json
{
  "family": "wasm-threat-detector",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "threat-detector",
      "image": "your-registry/wasm-threat-detector:latest",
      "memory": 512,
      "essential": true,
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/wasm-sentinel",
          "awslogs-region": "us-east-1"
        }
      }
    }
  ]
}
```

### Azure Container Instances

```yaml
apiVersion: 2018-10-01
location: eastus
name: wasm-sentinel
properties:
  containers:
  - name: sentinel
    properties:
      image: your-registry/wasm-sentinel:latest
      resources:
        requests:
          cpu: 1.0
          memoryInGb: 1.5
      ports:
      - port: 8080
  osType: Linux
  restartPolicy: Always
```
