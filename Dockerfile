# 多阶段构建 Dockerfile

# 构建阶段 - 使用 Debian 镜像以兼容 wasmtime-go
FROM golang:1.26-bookworm AS go-builder

# 安装构建依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates curl build-essential \
    && rm -rf /var/lib/apt/lists/*

# 安装 Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup target add wasm32-wasip1

WORKDIR /app

# 复制依赖文件并下载Go依赖
COPY host/go.mod host/go.sum ./host/
RUN cd host && go mod download

# 复制Rust项目配置和创建占位符以允许cargo fetch
COPY rules/suspicious-shell/Cargo.toml rules/suspicious-shell/Cargo.lock ./rules/suspicious-shell/
RUN mkdir -p rules/suspicious-shell/src && echo "// placeholder" > rules/suspicious-shell/src/lib.rs
RUN cd rules/suspicious-shell && cargo fetch

# 复制源代码（会覆盖占位符）
COPY . .

# 构建应用
RUN chmod +x scripts/build.sh && ./scripts/build.sh

# 运行时阶段 - 使用精简 Debian 镜像
FROM debian:bookworm-slim

# 安装运行时依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget procps curl \
    && rm -rf /var/lib/apt/lists/*

# 创建非 root 用户
RUN groupadd -g 1001 wasm && \
    useradd -u 1001 -g wasm -s /bin/false wasm

WORKDIR /app

# 从构建阶段复制文件
COPY --from=go-builder /app/wasmsentinel .
COPY --from=go-builder /app/rules ./rules
COPY --from=go-builder /app/examples ./examples

# 创建必要的目录
RUN mkdir -p /var/log /etc/wasmsentinel && \
    chown -R wasm:wasm /app /var/log /etc/wasmsentinel

# 切换到非 root 用户
USER wasm

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# 暴露端口
EXPOSE 8080

# 设置入口点
ENTRYPOINT ["./wasmsentinel"]

# 默认参数
CMD ["--rules", "./rules", "--log-level", "info", "--metrics-port", "8080"]
