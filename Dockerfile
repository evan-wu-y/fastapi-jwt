# 使用独立 Python 构建的多阶段镜像示例
# 第一阶段：在 `/app` 目录中构建应用

FROM ghcr.io/astral-sh/uv:bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

# 配置 Python 目录以保持一致
ENV UV_PYTHON_INSTALL_DIR=/python

# 只使用托管 Python 版本
ENV UV_PYTHON_PREFERENCE=only-managed

# 在安装项目之前先安装 Python（用于缓存）
RUN uv python install 3.13

WORKDIR /app

# 使用锁文件安装项目依赖（不安装项目本身）
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev

# 复制项目源代码并安装项目本身
COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

# 第二阶段：使用不包含 uv 的最终镜像
FROM debian:bookworm-slim

# 创建非 root 用户
RUN groupadd --system --gid 999 nonroot \
 && useradd --system --gid 999 --uid 999 --create-home nonroot

# 复制 Python 版本
COPY --from=builder /python /python

# 从构建阶段复制应用（设置正确的所有权）
COPY --from=builder --chown=nonroot:nonroot /app /app

# 将虚拟环境中的可执行文件放在 PATH 前面
ENV PATH="/app/.venv/bin:/python/bin:$PATH"

# 使用非 root 用户运行应用
USER nonroot

# 设置工作目录
WORKDIR /app

# 暴露端口
EXPOSE 8000

# 运行 FastAPI 应用
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
