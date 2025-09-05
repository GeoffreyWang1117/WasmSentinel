# 多阶段构建 Dockerfile

# 构建阶段
FROM golang:1.21-alpine AS go-builder

# 安装构建依赖
RUN apk add --no-cache git ca-certificates tzdata curl build-base

# 安装 Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup target add wasm32-wasi

WORKDIR /app

# 复制依赖文件
COPY host/go.mod host/go.sum ./host/
COPY rules/suspicious-shell/Cargo.toml rules/suspicious-shell/Cargo.lock ./rules/suspicious-shell/

# 下载依赖
RUN cd host && go mod download
RUN cd rules/suspicious-shell && cargo fetch

# 复制源代码
COPY . .

# 构建应用
RUN chmod +x scripts/build.sh && ./scripts/build.sh

# 运行时阶段
FROM alpine:latest

# 安装运行时依赖
RUN apk --no-cache add ca-certificates tzdata

# 创建非 root 用户
RUN addgroup -g 1001 -S wasm && \
    adduser -u 1001 -S wasm -G wasm

WORKDIR /app

# 从构建阶段复制文件
COPY --from=go-builder /app/wasm-threat-detector .
COPY --from=go-builder /app/rules ./rules
COPY --from=go-builder /app/examples ./examples

# 创建必要的目录
RUN mkdir -p /var/log /etc/wasm-threat-detector && \
    chown -R wasm:wasm /app /var/log /etc/wasm-threat-detector

# 切换到非 root 用户
USER wasm

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# 暴露端口
EXPOSE 8080

# 设置入口点
ENTRYPOINT ["./wasm-threat-detector"]

# 默认参数
CMD ["--rules", "./rules", "--log-level", "info", "--metrics-port", "8080"]
