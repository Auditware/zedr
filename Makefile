include secrets/.env.local
export

secrets/.env.local:
	$(error secrets/.env.local is missing. Copy secrets/.env.local.example to secrets/.env.local and fill it in)

ZEDR_VM_USER ?= zedr
ZEDR_VM_PASSWORD ?= zedr
ZEDR_VM_LINUX_PORT ?= 2224
ZEDR_VM_WINDOWS_PORT ?= 2222
ZEDR_VM_MACOS_PORT ?= 22223

.PHONY: help
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'


.PHONY: setup
setup: ## Set up development environment (macOS only)
	@[ "$$(uname)" = "Darwin" ] || (echo "Error: This project requires macOS" && exit 1)
	@echo "Installing dependencies..."
	@command -v brew >/dev/null 2>&1 || (echo "Error: Homebrew required. Install from https://brew.sh/" && exit 1)
	@command -v rustc >/dev/null 2>&1 || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
	@command -v sshpass >/dev/null 2>&1 || brew install hudochenkov/sshpass/sshpass
	@git config core.hooksPath .githooks
	@command git config --list | grep hooks
	@echo "✓ Development tools installed"
	@echo ""
	@echo "VM Setup Required:"
	@echo "  Developers must provision their own test VMs"
	@echo "  See docs/VM_SETUP.md for setup instructions"
	@echo ""
	@echo "VM Requirements:"
	@echo "  - Linux VM: SSH on localhost:$(ZEDR_VM_LINUX_PORT) (user: $(ZEDR_VM_USER), password: $(ZEDR_VM_PASSWORD))"
	@echo "  - Windows VM: SSH on localhost:$(ZEDR_VM_WINDOWS_PORT) (user: $(ZEDR_VM_USER), password: $(ZEDR_VM_PASSWORD))"
	@echo "  - macOS VM: SSH on localhost:$(ZEDR_VM_MACOS_PORT) (user: $(ZEDR_VM_USER), password: $(ZEDR_VM_PASSWORD))"


.PHONY: build
build: ## Build all agents
	@echo "Building agents requires VMs. Use specific test targets:"
	@echo "  make test-linux    - Test Linux agent (port $(ZEDR_VM_LINUX_PORT))"
	@echo "  make test-windows  - Test Windows agent (port $(ZEDR_VM_WINDOWS_PORT))"
	@echo "  make test-macos    - Test macOS agent (port $(ZEDR_VM_MACOS_PORT))"

.PHONY: start
start:
	$(MAKE) dev

.PHONY: stop
stop:
	$(MAKE) dev-stop

.PHONY: vm-baseline-linux
vm-baseline-linux: ## Install dependencies in Linux VM (baseline for snapshot)
	@echo "Installing dependencies in Linux VM..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_LINUX_PORT) $(ZEDR_VM_USER)@localhost 'bash -l -c "sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source ~/.cargo/env && rustc --version && echo '\''✓ Linux VM baseline complete. Ready for snapshot.'\''"'

.PHONY: vm-baseline-windows
vm-baseline-windows: ## Install dependencies in Windows VM (baseline for snapshot)
	@echo "Installing dependencies in Windows VM..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost 'powershell -Command "$$ErrorActionPreference = \"Stop\"; \
		Write-Host \"Ensuring SSH service starts on boot...\"; \
		Set-Service -Name sshd -StartupType Automatic; \
		Write-Host \"Installing Visual Studio Build Tools with ARM64 support and Clang/LLVM (this may take 15-20 minutes)...\"; \
		$$vsInstaller = \"$$env:TEMP\\vs_buildtools.exe\"; \
		Invoke-WebRequest -Uri \"https://aka.ms/vs/17/release/vs_buildtools.exe\" -OutFile $$vsInstaller; \
		Start-Process -FilePath $$vsInstaller -ArgumentList \"--quiet\", \"--wait\", \"--norestart\", \"--nocache\", \"--add\", \"Microsoft.VisualStudio.Workload.VCTools\", \"--add\", \"Microsoft.VisualStudio.Component.VC.Tools.ARM64\", \"--add\", \"Microsoft.VisualStudio.Component.VC.Llvm.Clang\", \"--add\", \"Microsoft.VisualStudio.Component.VC.Llvm.ClangToolset\", \"--includeRecommended\" -Wait -NoNewWindow; \
		Write-Host \"Installing CMake...\"; \
		winget install --id Kitware.CMake --silent --accept-package-agreements --accept-source-agreements; \
		Write-Host \"Installing Rust for ARM64...\"; \
		$$rustupUrl = \"https://win.rustup.rs/aarch64\"; \
		$$rustupInstaller = \"$$env:TEMP\\rustup-init.exe\"; \
		Invoke-WebRequest -Uri $$rustupUrl -OutFile $$rustupInstaller; \
		Start-Process -FilePath $$rustupInstaller -ArgumentList \"-y\", \"--default-host\", \"aarch64-pc-windows-msvc\" -Wait -NoNewWindow; \
		$$env:Path = [System.Environment]::GetEnvironmentVariable(\"Path\", \"User\") + \";\" + [System.Environment]::GetEnvironmentVariable(\"Path\", \"Machine\") + \";C:\\Program Files\\CMake\\bin\"; \
		rustc --version; \
		cmake --version; \
		Write-Host \"✓ Windows VM baseline complete. Ready for snapshot.\""'

.PHONY: vm-baseline-macos
vm-baseline-macos: ## Install dependencies in macOS VM (baseline for snapshot)
	@echo "Installing dependencies in macOS VM..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no $(ZEDR_VM_USER)@$(ZEDR_VM_MACOS_IP) 'bash -l -c "command -v xcode-select >/dev/null 2>&1 || xcode-select --install && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source ~/.cargo/env && rustc --version && echo '\''✓ macOS VM baseline complete. Ready for snapshot.'\''"'

.PHONY: vm-baseline-all
vm-baseline-all: vm-baseline-linux vm-baseline-windows vm-baseline-macos ## Baseline all VMs

.PHONY: deploy-windows
deploy-windows: ## Deploy agent code to Windows VM and build
	@echo "Deploying agent to Windows VM..."
	@echo "Cleaning up previous artifacts and services..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost 'powershell -Command "$$ErrorActionPreference = \"SilentlyContinue\"; Stop-Service -Name zedr-agent -Force; sc.exe delete zedr-agent; Remove-Item -Path C:\zedr -Recurse -Force; Remove-Item -Path \"C:\Program Files\zedr\" -Recurse -Force; $$ErrorActionPreference = \"Stop\""'
	@echo "Creating clean directory structure..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost "cmd /c \"mkdir C:\zedr\agent\windows\src && mkdir C:\zedr\agent\shared\src && mkdir C:\zedr\protocol\src\""
	@echo "Copying protocol..."
	@sshpass -p $(ZEDR_VM_PASSWORD) scp -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -P $(ZEDR_VM_WINDOWS_PORT) protocol/Cargo.toml $(ZEDR_VM_USER)@localhost:C:/zedr/protocol/
	@sshpass -p $(ZEDR_VM_PASSWORD) scp -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -P $(ZEDR_VM_WINDOWS_PORT) protocol/src/lib.rs $(ZEDR_VM_USER)@localhost:C:/zedr/protocol/src/
	@echo "Copying shared..."
	@sshpass -p $(ZEDR_VM_PASSWORD) scp -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -P $(ZEDR_VM_WINDOWS_PORT) agent/shared/Cargo.toml $(ZEDR_VM_USER)@localhost:C:/zedr/agent/shared/
	@sshpass -p $(ZEDR_VM_PASSWORD) scp -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -P $(ZEDR_VM_WINDOWS_PORT) agent/shared/src/*.rs $(ZEDR_VM_USER)@localhost:C:/zedr/agent/shared/src/
	@echo "Copying Windows agent..."
	@sshpass -p $(ZEDR_VM_PASSWORD) scp -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -P $(ZEDR_VM_WINDOWS_PORT) agent/windows/Cargo.toml agent/windows/install.ps1 agent/windows/uninstall.ps1 $(ZEDR_VM_USER)@localhost:C:/zedr/agent/windows/
	@sshpass -p $(ZEDR_VM_PASSWORD) scp -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -P $(ZEDR_VM_WINDOWS_PORT) agent/windows/src/*.rs $(ZEDR_VM_USER)@localhost:C:/zedr/agent/windows/src/
	@echo "Building agent on Windows VM..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost "cd C:\zedr\agent && cargo build --release --package zedr-agent-windows"
	@echo "✓ Windows agent built successfully"
	@echo "Copying binary back to control server..."
	@mkdir -p control_server/backend/binaries/v0.1.0/windows/arm64
	@sshpass -p $(ZEDR_VM_PASSWORD) scp -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -P $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost:C:/zedr/agent/target/release/zedr-agent-windows.exe control_server/backend/binaries/v0.1.0/windows/x64/zedr-agent.exe
	@echo "Verifying binary placement and architecture..."
	@test -f control_server/backend/binaries/v0.1.0/windows/arm64/zedr-agent.exe || (echo "ERROR: Binary not found at expected location" && exit 1)
	@file control_server/backend/binaries/v0.1.0/windows/arm64/zedr-agent.exe | grep -q "PE32.*executable.*x86-64" || (echo "ERROR: Binary is not x64 Windows PE executable" && exit 1)
	@ls -lh control_server/backend/binaries/v0.1.0/windows/arm64/zedr-agent.exe
	@echo "✓ Binary verified: Windows arm64 PE executable ready for distribution"

.PHONY: build-windows-binary
build-windows-binary: ## Build Windows agent binary and copy to control server
	@echo "Building Windows agent binary (latest code)..."
	@echo "Checking Windows VM availability..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost "echo VM reachable" 2>/dev/null || \
		(echo "ERROR: Windows VM not reachable on localhost:$(ZEDR_VM_WINDOWS_PORT)" && \
		 echo "Start your Windows VM with SSH user $(ZEDR_VM_USER)/$(ZEDR_VM_PASSWORD)" && exit 1)
	@echo "Comprehensive cleanup of all zedr artifacts and services..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost 'powershell -Command "$$ErrorActionPreference = \"SilentlyContinue\"; \
		Write-Host \"Enumerating existing zedr services before cleanup:\"; \
		Get-Service | Where-Object { $$_.Name -like \"*zedr*\" } | Format-Table Name, Status, StartType; \
		Write-Host \"Enumerating zedr processes before cleanup:\"; \
		Get-Process | Where-Object { $$_.ProcessName -like \"*zedr*\" } | Format-Table ProcessName, Id, Path; \
		Write-Host \"Stopping and removing zedr services:\"; \
		Stop-Service -Name zedr-agent -Force; \
		sc.exe delete zedr-agent; \
		Write-Host \"Terminating zedr processes:\"; \
		Get-Process | Where-Object { $$_.ProcessName -like \"*zedr*\" } | Stop-Process -Force; \
		Write-Host \"Removing installation directories:\"; \
		Remove-Item -Path C:\zedr -Recurse -Force; \
		Remove-Item -Path \"C:\Program Files\zedr\" -Recurse -Force; \
		Remove-Item -Path \"C:\ProgramData\zedr\" -Recurse -Force; \
		Write-Host \"Clearing Cargo build cache:\"; \
		Remove-Item -Path \"$$env:USERPROFILE\.cargo\registry\cache\" -Recurse -Force; \
		Remove-Item -Path \"$$env:USERPROFILE\.cargo\.package-cache\" -Recurse -Force; \
		Write-Host \"Clearing Windows Event Logs:\"; \
		Get-EventLog -List | Where-Object { $$_.Log -eq \"Application\" } | ForEach-Object { Get-WinEvent -FilterHashtable @{LogName=\"Application\"; ProviderName=\"zedr-agent\"} -ErrorAction SilentlyContinue | ForEach-Object { wevtutil cl Application } }; \
		Write-Host \"Removing registry entries:\"; \
		Remove-Item -Path \"HKLM:\SYSTEM\CurrentControlSet\Services\zedr-agent\" -Recurse -Force; \
		Write-Host \"Cleaning temp artifacts:\"; \
		Remove-Item -Path \"$$env:TEMP\zedr*\" -Recurse -Force; \
		Remove-Item -Path \"$$env:TEMP\*zedr*\" -Recurse -Force; \
		Write-Host \"Verification - remaining zedr services:\"; \
		Get-Service | Where-Object { $$_.Name -like \"*zedr*\" } | Format-Table Name, Status, StartType; \
		Write-Host \"Verification - remaining zedr processes:\"; \
		Get-Process | Where-Object { $$_.ProcessName -like \"*zedr*\" } | Format-Table ProcessName, Id, Path; \
		Write-Host \"Verification - installation directories:\"; \
		Test-Path C:\zedr; Test-Path \"C:\Program Files\zedr\"; \
		$$ErrorActionPreference = \"Stop\""'
	@echo "Syncing latest agent code..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost "mkdir C:\zedr"
	@tar czf - --exclude='agent/target' agent/ protocol/ | sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost "cd C:\zedr && tar xzf -"
	@echo "Building release binary..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost 'powershell -Command "cd C:\zedr\agent; $$env:Path = [System.Environment]::GetEnvironmentVariable(\"Path\", \"User\") + \";\" + [System.Environment]::GetEnvironmentVariable(\"Path\", \"Machine\"); cargo build --release --package zedr-agent-windows"'
	@echo "Retrieving binary and verifying..."
	@ARCH=$$(sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost 'powershell -Command "if ($$env:PROCESSOR_ARCHITECTURE -eq \"ARM64\") { \"arm64\" } else { \"x64\" }"' | tr -d '\r\n' | sed 's/[^a-zA-Z0-9]//g') && \
	rm -f control_server/backend/binaries/v0.1.0/windows/zedr-agent.exe control_server/backend/binaries/v0.1.0/windows/*/zedr-agent.exe && \
	mkdir -p control_server/backend/binaries/v0.1.0/windows/$$ARCH && \
	sshpass -p $(ZEDR_VM_PASSWORD) scp -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -P $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost:C:/zedr/agent/target/release/zedr-agent-windows.exe control_server/backend/binaries/v0.1.0/windows/$$ARCH/zedr-agent.exe && \
	test -f control_server/backend/binaries/v0.1.0/windows/$$ARCH/zedr-agent.exe || (echo "ERROR: Binary copy failed" && exit 1) && \
	file control_server/backend/binaries/v0.1.0/windows/$$ARCH/zedr-agent.exe | grep -q "PE32.*executable.*Windows" || (echo "ERROR: Invalid binary format" && exit 1) && \
	ls -lh control_server/backend/binaries/v0.1.0/windows/$$ARCH/zedr-agent.exe && \
	echo "✓ Windows $$ARCH binary built and ready for control server distribution"

LINUX_ARCHES ?= x64 arm64

# Builds one static Linux binary per architecture in LINUX_ARCHES and copies it to where the control server serves it from.
# $(1) is the file name, $(2) the docker build arguments
define build_linux_static
	@set -e; for arch in $(LINUX_ARCHES); do \
		case $$arch in \
			x64) platform=linux/amd64; machine=x86-64 ;; \
			arm64) platform=linux/arm64; machine=aarch64 ;; \
			*) echo "ERROR: unknown architecture $$arch, use x64 or arm64"; exit 1 ;; \
		esac; \
		out=control_server/backend/binaries/v0.1.0/linux/$$arch; \
		mkdir -p $$out; \
		docker build $(2) --target binary --platform $$platform --output type=local,dest=$$out .; \
		file $$out/$(1) | grep -q "ELF 64-bit.*$$machine.*static" || { echo "ERROR: $$out/$(1) is not a static $$machine ELF"; exit 1; }; \
		ls -lh $$out/$(1); \
	done
endef

.PHONY: build-linux-binary
build-linux-binary: ## Build the static Linux agent in containers and copy it to the control server, LINUX_ARCHES picks x64, arm64 or both
	$(call build_linux_static,zedr-agent,--file agent/linux/Dockerfile)

.PHONY: guest
guest: ## Build the rule program a proof is about, reproducibly in a container, and print its image ID
	@cargo risczero build --manifest-path prover/guest/Cargo.toml

GUEST_BIN := $(abspath prover/guest/target/riscv32im-risc0-zkvm-elf/docker/zedr-guest.bin)

.PHONY: prover
prover: ## Build the prover for this machine around the rule program from `make guest`
	@test -f $(GUEST_BIN) || (echo "ERROR: run 'make guest' first" && exit 1)
	@ZEDR_GUEST_BIN=$(GUEST_BIN) cargo build --release --manifest-path prover/host/Cargo.toml
	@prover/host/target/release/zedr-prover image-id

.PHONY: build-linux-prover
build-linux-prover: ## Build the static Linux prover around the rule program from `make guest` and copy it to the control server, which hands it to endpoints with the agent
	@test -f $(GUEST_BIN) || (echo "ERROR: run 'make guest' first" && exit 1)
	$(call build_linux_static,zedr-prover,--file prover/Dockerfile --build-context guest="$(dir $(GUEST_BIN))")

.PHONY: test-zk
test-zk: guest prover ## Prove and verify a small window for real, this takes minutes
	@prover/host/target/release/zedr-prover selftest

NATIVE_LINUX_ARCH := $(if $(filter arm64 aarch64,$(shell uname -m)),arm64,x64)

.PHONY: simulator-image
simulator-image: ## Build the image of the development simulator, which plays endpoints from a scenario file
	@docker build --file agent/linux/Dockerfile --target simulator -t zedr-simulator:dev .

.PHONY: test-e2e-linux
test-e2e-linux: guest agent-image simulator-image ## Run the whole flow for real: control server, an endpoint set up by the installer, sealed telemetry, a finding, verified proofs, and an endpoint caught holding a match back. This takes a while
	@$(MAKE) build-linux-binary build-linux-prover LINUX_ARCHES=$(NATIVE_LINUX_ARCH)
	@cargo build --release --manifest-path control_server/backend/Cargo.toml
	@node e2e/linux-flow.mjs

.PHONY: test-linux-container
test-linux-container: ## Test the shared and Linux agent code in a Linux container
	@docker build --file agent/linux/Dockerfile --target test --progress plain .

.PHONY: agent-image
agent-image: ## Build the agent container image locally
	@docker build -t zedr-agent:dev deploy/agents/container

.PHONY: vm-snapshot-macos
vm-snapshot-macos: ## Create Baseline snapshot for macOS VM (Tart)
	@echo "Creating macOS VM snapshot 'Baseline'..."
	@tart stop zedr-macos 2>/dev/null || true
	@tart delete zedr-macos-baseline 2>/dev/null || true
	@tart clone zedr-macos zedr-macos-baseline
	@tart run --no-graphics --net-bridged=en0 zedr-macos &
	@echo "✓ macOS VM snapshot 'zedr-macos-baseline' created"

.PHONY: vm-restore-macos
vm-restore-macos: ## Restore macOS VM to Baseline snapshot
	@echo "Restoring macOS VM to Baseline snapshot..."
	@tart stop zedr-macos 2>/dev/null || true
	@tart delete zedr-macos 2>/dev/null || true
	@tart clone zedr-macos-baseline zedr-macos
	@tart run --no-graphics --net-softnet --net-softnet-expose $(ZEDR_VM_MACOS_PORT):22 zedr-macos &
	@sleep 5
	@echo "✓ macOS VM restored to Baseline"

.PHONY: test
test: ## Run all tests (platform-aware)
	@echo "Running tests (excluding platform-specific code for current OS)..."
	@echo "=== Protocol Tests ==="
	@cd protocol && cargo test
	@echo ""
	@echo "=== Ledger Tests ==="
	@cd ledger && cargo test --features seal
	@echo ""
	@echo "=== Rules Tests ==="
	@cd rules && cargo test
	@echo ""
	@echo "=== Console Tests ==="
	@cd control_server/frontend && { [ -d node_modules ] || npm ci --no-audit --no-fund; } && npm test
	@echo ""
	@echo "=== Agent Tests ==="
	@if [ "$$(uname)" = "Darwin" ]; then \
		cd agent && cargo test --workspace --exclude zedr-agent-windows --exclude zedr-agent-linux -- --nocapture; \
	elif [ "$$(uname)" = "Linux" ]; then \
		cd agent && cargo test --workspace --exclude zedr-agent-windows --exclude zedr-agent-macos -- --nocapture; \
	else \
		echo "Unsupported OS for local testing. Use platform-specific test targets."; \
		exit 1; \
	fi
	@echo ""
	@echo "=== Backend Tests ==="
	@cd control_server/backend && cargo test --lib
	@echo ""
	@echo "=== Backend Integration Tests ==="
	@cd control_server/backend && cargo test --test integration_test

.PHONY: test-macos
test-macos: ## Test macOS agent in VM (Tart)
	@echo "Checking macOS VM availability (IP $(ZEDR_VM_MACOS_IP))..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no $(ZEDR_VM_USER)@$(ZEDR_VM_MACOS_IP) "echo VM reachable" 2>/dev/null || \
		(echo "ERROR: macOS VM not reachable at $(ZEDR_VM_MACOS_IP)" && \
		 echo "Start Tart VM with: tart run --net-bridged=en0 zedr-macos" && exit 1)
	@echo "Syncing agent code to macOS VM..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no $(ZEDR_VM_USER)@$(ZEDR_VM_MACOS_IP) "rm -rf agent && mkdir -p agent"
	@cd agent && tar czf - Cargo.toml macos/ shared/ windows/Cargo.toml windows/src/main.rs linux/Cargo.toml linux/src/main.rs | sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no $(ZEDR_VM_USER)@$(ZEDR_VM_MACOS_IP) "cd agent && tar xzf -"
	@echo "Building and testing macOS agent..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no $(ZEDR_VM_USER)@$(ZEDR_VM_MACOS_IP) "cd agent && source ~/.cargo/env && cargo test -p zedr-agent-macos -- --nocapture"

.PHONY: test-linux
test-linux: ## Test Linux agent in VM
	@echo "Checking Linux VM availability (port $(ZEDR_VM_LINUX_PORT))..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_LINUX_PORT) $(ZEDR_VM_USER)@localhost "echo VM reachable" 2>/dev/null || \
		(echo "ERROR: Linux VM not reachable on localhost:$(ZEDR_VM_LINUX_PORT)" && \
		 echo "Start your Linux VM with SSH user $(ZEDR_VM_USER)/$(ZEDR_VM_PASSWORD)" && exit 1)
	@echo "Syncing agent code to Linux VM..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_LINUX_PORT) $(ZEDR_VM_USER)@localhost "rm -rf agent && mkdir -p agent"
	@cd agent && tar czf - Cargo.toml linux/ shared/ windows/Cargo.toml windows/src/main.rs macos/Cargo.toml macos/src/main.rs | sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_LINUX_PORT) $(ZEDR_VM_USER)@localhost "cd agent && tar xzf -"
	@echo "Building and testing Linux agent..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_LINUX_PORT) $(ZEDR_VM_USER)@localhost 'bash -l -c "cd agent && cargo test -p zedr-agent-linux -- --nocapture"'

.PHONY: test-windows
test-windows: ## Test Windows agent in VM
	@echo "Checking Windows VM availability (port $(ZEDR_VM_WINDOWS_PORT))..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost "echo VM reachable" 2>/dev/null || \
		(echo "ERROR: Windows VM not reachable on localhost:$(ZEDR_VM_WINDOWS_PORT)" && \
		 echo "Start your Windows VM manually in VMware Fusion" && exit 1)
	@echo "Syncing agent code to Windows VM..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost "if exist agent rmdir /s /q agent && mkdir agent"
	@cd agent && tar czf - Cargo.toml windows/ shared/ linux/Cargo.toml linux/src/main.rs macos/Cargo.toml macos/src/main.rs | sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost "cd agent && tar xzf -"
	@echo "Building and testing Windows agent..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost 'powershell -Command "cd agent; $$env:Path = [System.Environment]::GetEnvironmentVariable(\"Path\", \"User\") + \";\" + [System.Environment]::GetEnvironmentVariable(\"Path\", \"Machine\"); cargo test -p zedr-agent-windows -- --nocapture"'

.PHONY: clean
clean: ## Clean build artifacts
	cd agent && cargo clean

.PHONY: clean-vm-windows
clean-vm-windows: ## Complete zedr cleanup on Windows VM with verification
	@echo "Performing complete zedr cleanup on Windows VM..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost 'cmd /c "rmdir /s /q C:\\zedr 2>nul & rmdir /s /q \"C:\\Program Files\\zedr\" 2>nul & rmdir /s /q C:\\ProgramData\\zedr 2>nul & exit 0"'
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost 'powershell -Command "$$ErrorActionPreference = \"SilentlyContinue\"; \
		Write-Host \"=== CLEANUP PHASE ==="; \
		Write-Host \"Stopping all zedr services...\"; \
		Get-Service | Where-Object { $$_.Name -like \"*zedr*\" } | Stop-Service -Force; \
		Write-Host \"Deleting all zedr services...\"; \
		Get-Service | Where-Object { $$_.Name -like \"*zedr*\" } | ForEach-Object { sc.exe delete $$_.Name }; \
		Write-Host \"Terminating all zedr processes...\"; \
		Get-Process | Where-Object { $$_.ProcessName -like \"*zedr*\" } | Stop-Process -Force; \
		Write-Host \"Removing registry entries...\"; \
		Get-ChildItem \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\" | Where-Object { $$_.Name -like \"*zedr*\" } | Remove-Item -Recurse -Force; \
		Write-Host \"Clearing temp files...\"; \
		Remove-Item -Path \"$$env:TEMP\\*zedr*\" -Recurse -Force; \
		Write-Host \"\"; \
		Write-Host \"=== VERIFICATION PHASE ==="; \
		$$services = Get-Service | Where-Object { $$_.Name -like \"*zedr*\" }; \
		$$processes = Get-Process | Where-Object { $$_.ProcessName -like \"*zedr*\" }; \
		$$programFiles = Test-Path \"C:\\Program Files\\zedr\"; \
		$$programData = Test-Path \"C:\\ProgramData\\zedr\"; \
		$$buildDir = Test-Path \"C:\\zedr\"; \
		Write-Host \"Services found: $$(@($$services).Count)\"; \
		Write-Host \"Processes found: $$(@($$processes).Count)\"; \
		Write-Host \"Program Files exists: $$programFiles\"; \
		Write-Host \"ProgramData exists: $$programData\"; \
		Write-Host \"Build directory exists: $$buildDir\"; \
		Write-Host \"\"; \
		if ($$services -or $$processes -or $$programFiles -or $$programData -or $$buildDir) { \
			Write-Host \"✗ CLEANUP INCOMPLETE - artifacts remain\" -ForegroundColor Red; \
			if ($$services) { $$services | Format-Table Name, Status, StartType }; \
			if ($$processes) { $$processes | Format-Table ProcessName, Id, Path }; \
			exit 1 \
		} else { \
			Write-Host \"✓ CLEANUP VERIFIED - VM is completely clean\" -ForegroundColor Green \
		}"'

.PHONY: clean-db
clean-db: ## Reset database for fresh agent testing
	@echo "Resetting database for fresh agent testing..."
	@cd control_server/backend && sqlite3 zedr.db "DELETE FROM agent_sessions; DELETE FROM incidents; DELETE FROM agent_installations; DELETE FROM upgrade_commands; DELETE FROM agents; DELETE FROM events; DELETE FROM install_keys; DELETE FROM enrollment_tokens;"
	@echo "✓ Database cleared of agent data, events, and install keys"

.PHONY: setup-tls
setup-tls: ## Generate TLS certificates from ZEDR_SERVER_URL
	@echo "Generating TLS certificates from ZEDR_SERVER_URL..."
	@mkdir -p control_server/certs
	@source secrets/.env.server.local && \
	SERVER_HOST=$$(echo $$ZEDR_SERVER_URL | sed 's|.*://||; s|:.*||') && \
	echo "Generating certificate for: $$SERVER_HOST" && \
	openssl req -x509 -newkey rsa:4096 \
		-keyout control_server/certs/key.pem \
		-out control_server/certs/cert.pem \
		-days 365 -nodes \
		-subj "/CN=$$SERVER_HOST" \
		-addext "subjectAltName=DNS:localhost,DNS:$$SERVER_HOST,IP:127.0.0.1,IP:$$SERVER_HOST" \
		-addext "extendedKeyUsage=serverAuth,clientAuth"
	@echo "✓ TLS certificates generated for $$SERVER_HOST"

.PHONY: clean-agents
clean-agents: ## Clear agents and alerts/events only
	@echo "Clearing agents and alerts/events..."
	@cd control_server/backend && sqlite3 ../zedr.db "DELETE FROM agents; DELETE FROM events WHERE agent_id IS NOT NULL;"
	@echo "✓ Agents and alerts cleared (keeping install keys for reuse)"

# TODO: remove hardcoded passwords (use .env.server.local instead)
.PHONY: test-install-windows-through-control-server
test-install-windows-through-control-server: ## Install and test agent through control server APIs
	@echo "Testing agent installation through control server..."
	@echo "Starting control server..."
	@$(MAKE) dev > /dev/null 2>&1 &
	@sleep 5
	@echo "Generating install key and executing installation..."
	@source secrets/.env.server.local; \
	JWT_TOKEN=$$(curl -k -s -X POST https://localhost:7770/api/auth/login -H "Content-Type: application/json" -d "{\"username\": \"admin\", \"password\": \"$$ADMIN_PASSWORD\"}" | jq -r .token); \
	INSTALL_CMD=$$(curl -k -s -H "Authorization: Bearer $$JWT_TOKEN" -X POST https://localhost:7770/api/admin/installers/generate -H "Content-Type: application/json" -d '{"agent_version": "0.1.0"}' | jq -r .windows_command); \
	echo "Installing agent on Windows VM with command: $$INSTALL_CMD"; \
	sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost "powershell -Command \"$$INSTALL_CMD\""
	@echo "Verifying agent installation and service..."
	@sshpass -p $(ZEDR_VM_PASSWORD) ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p $(ZEDR_VM_WINDOWS_PORT) $(ZEDR_VM_USER)@localhost 'powershell -Command "Get-Service zedr-agent; Get-Process zedr-agent -ErrorAction SilentlyContinue"'
	@echo "✓ Agent installation through control server completed"

.PHONY: test-agent-install-windows
test-agent-install-windows: clean-db build-windows-binary test-install-windows-through-control-server ## Full end-to-end Windows agent installation test
	@echo "✓ Full end-to-end agent installation test completed"

.PHONY: fmt
fmt: ## Format code
	cd agent && cargo fmt --all

.PHONY: fmt-check
fmt-check: ## Check code formatting
	cd agent && cargo fmt --all -- --check

.PHONY: clippy
AGENT_ELSEWHERE := $(if $(filter Darwin,$(shell uname)),--exclude zedr-agent-windows --exclude zedr-agent-linux,--exclude zedr-agent-windows --exclude zedr-agent-macos)

clippy: ## Run clippy on the agent of this platform, its shared crates and the control server
	cd agent && cargo clippy --workspace $(AGENT_ELSEWHERE) --all-targets -- -D warnings
	cd control_server/backend && cargo clippy --all-targets -- -D warnings

.PHONY: ci
ci: fmt-check clippy test ## Run CI checks

.PHONY: dev
dev: ## Start full stack (backend + frontend) with pm2
	@echo "Starting zedr full stack (backend on :7770, frontend on :7771)..."
	@export $$(grep -v '^#' secrets/.env.server.local | xargs) && cd control_server && pm2 start ecosystem.config.js
	@sleep 3
	@echo ""
	@echo "✓ Services started:"
	@echo "  Backend:  http://localhost:7770"
	@echo "  Frontend: http://localhost:7771 (opens automatically)"
	@echo "  API Docs: http://localhost:7770/api-docs/openapi.json"
	@echo ""
	@pm2 status

.PHONY: dev-stop
dev-stop: ## Stop all services
	@echo "Stopping zedr services..."
	@pm2 stop zedr-backend zedr-frontend
	@pm2 delete zedr-backend zedr-frontend

.PHONY: dev-logs
dev-logs: ## Show logs for all services
	@pm2 logs --lines 50 --nostream

.PHONY: dev-logs-backend
dev-logs-backend: ## Show backend logs
	@pm2 logs zedr-backend --lines 50 --nostream

.PHONY: frontend-dev
frontend-dev: ## Start frontend development server only
	@echo "Starting frontend dev server on http://localhost:7771..."
	@cd control_server && pm2 start ecosystem.config.js --only zedr-frontend
	@pm2 logs zedr-frontend --lines 50 --nostream

.PHONY: dev-status
dev-status: ## Show service status
	@pm2 status

.PHONY: control-server-dev
control-server-dev: ## Start control server backend only
	@echo "Starting zedr backend..."
	@cd control_server && pm2 start ecosystem.config.js --only zedr-backend
	@pm2 logs zedr-backend --lines 20 --nostream

.PHONY: control-server-stop
control-server-stop: ## Stop control server
	@echo "Stopping zedr control server..."
	@pm2 stop zedr-backend
	@pm2 delete zedr-backend

.PHONY: control-server-logs
control-server-logs: ## Show control server logs
	@pm2 logs zedr-backend --lines 50 --nostream

.PHONY: control-server-status
control-server-status: ## Show control server status
	@pm2 status

.PHONY: demo
demo: ## Open the console on a test tenant: a simulated fleet with real intrusion stories in it. Its proof states are stand-ins, `make test-e2e-linux` proves for real
	@cargo build --bins --manifest-path control_server/backend/Cargo.toml
	@cd control_server/frontend && { [ -d node_modules ] || npm ci --no-audit --no-fund; } && npm run dev

.PHONY: frontend-deps
frontend-deps: ## Install frontend dependencies
	@echo "Installing frontend dependencies..."
	@cd control_server/frontend && npm install

.PHONY: frontend-build
frontend-build: ## Build frontend for production
	@echo "Building frontend..."
	@cd control_server/frontend && npm run build

.PHONY: codegen-api
codegen-api: ## Generate TypeScript API client from OpenAPI spec
	@echo "Generating TypeScript API client..."
	@cd control_server/frontend && npm run codegen

.PHONY: chart-lint
chart-lint: ## Lint the Helm chart with the CI values
	@helm lint deploy/chart --values deploy/chart/ci/ci-values.yaml

.PHONY: chart-template
chart-template: ## Render the Helm chart with the CI values
	@helm template zedr deploy/chart --namespace zedr --values deploy/chart/ci/ci-values.yaml

.PHONY: tf-validate
tf-validate: ## Format-check and validate the Terraform modules
	@terraform fmt -check -recursive deploy/terraform
	@terraform -chdir=deploy/terraform/aws init -backend=false
	@terraform -chdir=deploy/terraform/aws validate

.PHONY: deploy-lint
deploy-lint: chart-lint tf-validate ## Lint every deployment artifact
	@shellcheck deploy/argocd/bootstrap.sh
	@shellcheck --shell sh control_server/backend/src/api/install.sh deploy/agents/ec2/user-data.sh deploy/agents/container/entrypoint.sh

.PHONY: image-build
image-build: ## Build the control server image locally, with the agents and provers the build-linux targets put under control_server/backend/binaries
	@ls control_server/backend/binaries/v*/*/*/zedr-agent* >/dev/null 2>&1 || (echo "ERROR: no agent to serve, run 'make build-linux-binary' first, and 'make guest build-linux-prover' for endpoints that prove" && exit 1)
	@docker build -t zedr-control-server:dev .

.DEFAULT_GOAL := help
