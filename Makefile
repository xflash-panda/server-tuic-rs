# Makefile for server-tuic-rs project
# 便于测试、调试和构建

.PHONY: help build build-release build-agent build-agent-release test test-agent check check-agent clean run run-agent fmt clippy install

# 默认目标
.DEFAULT_GOAL := help

# 项目配置
CARGO := cargo
PACKAGE_AGENT := server-tuic-rs-agent
BINARY_NAME_AGENT := server-tuic-rs-agent
TARGET_DIR := target

# 颜色输出
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

##@ 帮助信息

help: ## 显示帮助信息
	@echo "$(GREEN)Server-TUIC Makefile$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "使用方法:\n  make $(YELLOW)<target>$(NC)\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(YELLOW)%s$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ 构建

build: ## 构建 debug 版本 (server-agent)
	@echo "$(GREEN)构建 debug 版本...$(NC)"
	$(CARGO) build -p $(PACKAGE_AGENT)

build-release: ## 构建 release 版本 (server-agent)
	@echo "$(GREEN)构建 release 版本...$(NC)"
	$(CARGO) build --release -p $(PACKAGE_AGENT)

build-agent: build ## 构建 server-agent (debug)

build-agent-release: build-release ## 构建 server-agent (release)

build-ring: ## 使用 ring 密码库构建 release 版本
	@echo "$(GREEN)使用 ring 构建 release 版本...$(NC)"
	$(CARGO) build --release -p $(PACKAGE_AGENT) --no-default-features --features ring

build-jemalloc: ## 启用 JEMalloc 构建 release 版本
	@echo "$(GREEN)启用 JEMalloc 构建 release 版本...$(NC)"
	$(CARGO) build --release -p $(PACKAGE_AGENT) --features jemallocator

##@ 测试

test: ## 运行所有测试
	@echo "$(GREEN)运行所有测试...$(NC)"
	$(CARGO) test

test-agent: ## 运行 server-agent 测试
	@echo "$(GREEN)运行 server-agent 测试...$(NC)"
	$(CARGO) test -p $(PACKAGE_AGENT)

test-verbose: ## 运行测试并显示详细输出
	@echo "$(GREEN)运行测试 (详细输出)...$(NC)"
	$(CARGO) test -- --nocapture

test-agent-verbose: ## 运行 server-agent 测试并显示详细输出
	@echo "$(GREEN)运行 server-agent 测试 (详细输出)...$(NC)"
	$(CARGO) test -p $(PACKAGE_AGENT) -- --nocapture

##@ 代码检查

check: ## 检查代码是否能编译
	@echo "$(GREEN)检查代码...$(NC)"
	$(CARGO) check

check-agent: ## 检查 server-agent 代码
	@echo "$(GREEN)检查 server-agent 代码...$(NC)"
	$(CARGO) check -p $(PACKAGE_AGENT)

clippy: ## 运行 clippy 进行代码检查
	@echo "$(GREEN)运行 clippy...$(NC)"
	$(CARGO) clippy -- -D warnings

clippy-agent: ## 对 server-agent 运行 clippy
	@echo "$(GREEN)对 server-agent 运行 clippy...$(NC)"
	$(CARGO) clippy -p $(PACKAGE_AGENT) -- -D warnings

fmt: ## 格式化代码
	@echo "$(GREEN)格式化代码...$(NC)"
	$(CARGO) fmt

fmt-check: ## 检查代码格式
	@echo "$(GREEN)检查代码格式...$(NC)"
	$(CARGO) fmt -- --check

##@ 运行

run: build ## 运行 server-agent (debug 版本，需要提供参数)
	@echo "$(YELLOW)提示: 需要提供运行参数，例如:$(NC)"
	@echo "  make run ARGS='--server_host 127.0.0.1 --port 8082 --node 1'"
	@if [ -z "$(ARGS)" ]; then \
		echo "$(RED)错误: 请提供 ARGS 参数$(NC)"; \
		exit 1; \
	fi
	$(TARGET_DIR)/debug/$(BINARY_NAME_AGENT) $(ARGS)

run-release: build-release ## 运行 server-agent (release 版本，需要提供参数)
	@echo "$(YELLOW)提示: 需要提供运行参数$(NC)"
	@if [ -z "$(ARGS)" ]; then \
		echo "$(RED)错误: 请提供 ARGS 参数$(NC)"; \
		exit 1; \
	fi
	$(TARGET_DIR)/release/$(BINARY_NAME_AGENT) $(ARGS)

run-agent: run ## 运行 server-agent (debug)

run-agent-release: run-release ## 运行 server-agent (release)

##@ 初始化

init-config: build ## 生成示例配置文件
	@echo "$(GREEN)生成示例配置文件...$(NC)"
	$(TARGET_DIR)/debug/$(BINARY_NAME_AGENT) --init

##@ 清理

clean: ## 清理构建产物
	@echo "$(GREEN)清理构建产物...$(NC)"
	$(CARGO) clean

clean-release: ## 仅清理 release 构建产物
	@echo "$(GREEN)清理 release 构建产物...$(NC)"
	rm -rf $(TARGET_DIR)/release

##@ 安装

install: build-release ## 安装到系统 (需要 root 权限)
	@echo "$(GREEN)安装 server-agent...$(NC)"
	sudo cp $(TARGET_DIR)/release/$(BINARY_NAME_AGENT) /usr/local/bin/
	@echo "$(GREEN)安装完成: /usr/local/bin/$(BINARY_NAME_AGENT)$(NC)"

uninstall: ## 从系统卸载
	@echo "$(GREEN)卸载 server-agent...$(NC)"
	sudo rm -f /usr/local/bin/$(BINARY_NAME_AGENT)
	@echo "$(GREEN)卸载完成$(NC)"

##@ 开发工具

watch: ## 监听文件变化并自动测试 (需要安装 cargo-watch)
	@echo "$(GREEN)监听文件变化...$(NC)"
	@command -v cargo-watch >/dev/null 2>&1 || { echo "$(RED)错误: 需要安装 cargo-watch$(NC)\n  cargo install cargo-watch"; exit 1; }
	cargo watch -x 'test -p $(PACKAGE_AGENT)'

watch-check: ## 监听文件变化并自动检查 (需要安装 cargo-watch)
	@echo "$(GREEN)监听文件变化...$(NC)"
	@command -v cargo-watch >/dev/null 2>&1 || { echo "$(RED)错误: 需要安装 cargo-watch$(NC)\n  cargo install cargo-watch"; exit 1; }
	cargo watch -x 'check -p $(PACKAGE_AGENT)'

doc: ## 生成文档
	@echo "$(GREEN)生成文档...$(NC)"
	$(CARGO) doc --no-deps --open

doc-private: ## 生成文档 (包含私有项)
	@echo "$(GREEN)生成文档 (包含私有项)...$(NC)"
	$(CARGO) doc --no-deps --document-private-items --open

##@ 快速命令

dev: check-agent test-agent ## 开发模式: 检查 + 测试
	@echo "$(GREEN)开发检查完成!$(NC)"

ci: fmt-check clippy test ## CI 模式: 格式检查 + clippy + 测试
	@echo "$(GREEN)CI 检查完成!$(NC)"

quick: check-agent ## 快速检查代码
	@echo "$(GREEN)快速检查完成!$(NC)"

all: clean build-release test ## 完整构建: 清理 + 构建 + 测试
	@echo "$(GREEN)完整构建完成!$(NC)"

##@ Git 快捷命令

git-status: ## 查看 git 状态
	@git status

git-diff: ## 查看改动
	@git diff

git-add: ## 添加所有改动
	@git add .

git-commit: ## 提交改动 (需要提供 MSG 参数)
	@if [ -z "$(MSG)" ]; then \
		echo "$(RED)错误: 请提供 MSG 参数$(NC)"; \
		echo "  make git-commit MSG='commit message'"; \
		exit 1; \
	fi
	@git commit -m "$(MSG)"

##@ 示例命令

example-run: ## 示例: 运行 server-agent
	@echo "$(YELLOW)示例命令:$(NC)"
	@echo "  make run ARGS='--server_host 127.0.0.1 --port 8082 --node 1 --cert_file /path/to/cert.crt --key_file /path/to/key.key'"
	@echo ""
	@echo "  make run-release ARGS='--server_host 127.0.0.1 --port 8082 --node 1'"

example-config: ## 示例: 生成配置文件
	@echo "$(YELLOW)示例命令:$(NC)"
	@echo "  make init-config"
	@echo "  编辑 config.toml 文件"
	@echo "  make run ARGS='--server_host 127.0.0.1 --port 8082 --node 1 --ext_conf_file config.toml'"
