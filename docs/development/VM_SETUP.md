# Test VM Setup

Developers provision their own test VMs:

- **Windows/Linux**: VMware Fusion, Parallels, UTM, VirtualBox
- **macOS**: Tart (VMware Fusion doesn't support macOS guest on Apple Silicon)

## Requirements

- **OS**: Ubuntu 24.04 (Linux), Windows 11 ARM64 (Windows), macOS Sequoia (macOS)
- **Architecture**: ARM64 for all OSes when running on Apple Silicon hosts
- **User**: Set in `secrets/.env.local` as `ZEDR_VM_USER` (default: `zedr`)
- **Password**: Set in `secrets/.env.local` as `ZEDR_VM_PASSWORD` (default: `zedr`)
- **SSH**: Enabled with password authentication
- **Networking**:
  - **Windows/Linux**: Port forwarding via `secrets/.env.local` (`ZEDR_VM_WINDOWS_PORT`: 2222, `ZEDR_VM_LINUX_PORT`: 2224)
  - **macOS**: Bridged networking with dynamic IP (use `tart ip zedr-macos` to get current IP, update `ZEDR_VM_MACOS_IP` in `secrets/.env.local`)

## Setup

1. **Install OS** with user `zedr`/`zedr`

2. **Configure SSH**:

   - **Linux**: `sudo apt update && sudo apt install openssh-server && sudo systemctl enable ssh && sudo systemctl start ssh`
   - **Windows** (PowerShell as Administrator):
     ```powershell
     Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
     Start-Service sshd
     Set-Service -Name sshd -StartupType 'Automatic'
     New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
     ```
   - **macOS**: System Settings → Sharing → Remote Login (or `sudo systemsetup -setremotelogin on`)

3. **Configure Port Forwarding**:

   ### For VMware Fusion (Mac host, Windows/Linux guests):

   VMware Fusion uses **NAT networking with port forwarding**, allowing SSH via `localhost:<port>`.

   **Get VM Network Info:**

   - In guest, get IP: `ipconfig` (Windows), `ip addr` (Linux)
   - On Mac, get MAC address: `cat "/var/db/vmware/vmnet-dhcpd-vmnet8.leases" | grep -B 5 "<VM_IP>"`

   **Set Static DHCP Reservation:**

   - Edit: `sudo nano "/Library/Preferences/VMware Fusion/vmnet8/dhcpd.conf"`
   - Add before closing `}`:
     ```
     host windows-zedr {
         hardware ethernet <MAC_ADDRESS>;
         fixed-address <VM_IP>;
     }
     ```

   **Configure Port Forwarding (NAT → localhost):**

   - Edit: `sudo nano "/Library/Preferences/VMware Fusion/vmnet8/nat.conf"`
   - Add under `[incomingtcp]` section:
     - `2222 = <VM_IP>:22` for Windows (forwards localhost:2222 → VM:22)
     - `2224 = <VM_IP>:22` for Linux (forwards localhost:2224 → VM:22)

   **Apply Changes:**

   ```bash
   sudo /Applications/VMware\ Fusion.app/Contents/Library/vmnet-cli --stop
   sudo /Applications/VMware\ Fusion.app/Contents/Library/vmnet-cli --start
   ```

   ### For Tart (Mac host, Mac guest):

   Tart uses **bridged networking** with dynamic IPs. Use `tart ip` to get the VM's current IP address.

   **Install Tart:**

   ```bash
   brew install cirruslabs/cli/tart
   tart clone ghcr.io/cirruslabs/macos-sequoia-base:latest zedr-macos
   tart set zedr-macos --cpu 4 --memory 8192 --disk-size 50
   ```

   **Start VM with bridged networking:**

   ```bash
   tart run --net-bridged=en0 zedr-macos
   ```

   **Setup in VM guest (complete these steps in order):**

   1. **VM comes with pre-configured admin user**

      - The base image has a default admin user already configured
      - We'll create a new `zedr` user for testing

   2. **Create zedr user**

      - Open **Terminal** app in the VM
      - Run these commands (use the default admin user's password when prompted):

        ```bash
        # Create zedr user with admin privileges
        sudo sysadminctl -addUser zedr -fullName "zedr" -password zedr -admin

        # Verify user was created
        dscl . -list /Users | grep zedr
        ```

   3. **Enable Remote Login (SSH)**

      - Open **System Settings** (click Apple menu → System Settings)
      - Click **General** in sidebar → **Sharing**
      - Toggle **Remote Login** ON
      - SSH is now enabled for all administrator users (including zedr)
   
   4. **Get VM IP address and test SSH**
   
      - On your host Mac terminal, get the VM's IP:
        ```bash
        tart ip zedr-macos
        ```
      - Update `secrets/.env.local` with this IP:
        ```bash
        ZEDR_VM_MACOS_IP=<VM_IP>
        ```
      - Test SSH connection:
        ```bash
        ssh zedr@<VM_IP>
        ```
      - Type `yes` to accept the fingerprint
      - Enter password: `zedr`
      - You should be logged in to the VM
      - Type `exit` to close connection

   5. **Verify SSH is configured correctly (run these in VM Terminal):**
      ```bash
      # Check if zedr user exists
      id zedr
      
      # Check if Remote Login (SSH) is enabled
      sudo systemsetup -getremotelogin
      # Should show: "Remote Login: On"
      
      # Check if SSH service is running
      sudo launchctl list | grep ssh
      # Should show: com.openssh.sshd
      
      # Check what port SSH is listening on
      sudo lsof -i -P | grep LISTEN | grep ssh
      # Should show: sshd listening on *.22
      ```
   
   6. **Test with sshpass from host (for automation):**
      ```bash
      sshpass -p zedr ssh -o StrictHostKeyChecking=no zedr@<VM_IP> "echo SSH works"
      ```
      - Should print: `SSH works`

4. **Test SSH**:

   - **Windows**: `sshpass -p zedr ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -p 2222 zedr@localhost "echo SSH works"`
   - **Linux**: `sshpass -p zedr ssh -o StrictHostKeyChecking=no -p 2224 zedr@localhost "echo SSH works"`
   - **macOS**: `sshpass -p zedr ssh -o StrictHostKeyChecking=no zedr@$(tart ip zedr-macos) "echo SSH works"`

5. **Baseline VM with Dependencies**:

   - **Windows**: `make vm-baseline-windows` (installs Visual Studio Build Tools with ARM64 support and Rust aarch64-pc-windows-msvc toolchain, takes 10-15 minutes)
   - **Linux**: `make vm-baseline-linux`
   - **macOS**: `make vm-baseline-macos`

   This installs required build tools and Rust toolchain. Verify installation:

   - **Windows PowerShell**: `rustc --version` (should show aarch64-pc-windows-msvc) and `cargo --version`
   - **Linux/macOS**: `rustc --version` and `cargo --version`

6. **Create "Baseline" Snapshot**:

   After SSH is configured and Rust is installed, create a snapshot to save this clean state:

7. **Snapshot Management**:

   After SSH is configured and dependencies are installed via `make vm-baseline-*`, create a clean "Baseline" snapshot:

   **VMware Fusion (Windows/Linux) - Manual:**

   1. In VMware Fusion GUI: **Virtual Machine** → **Snapshots** → **Take Snapshot**
   2. Name: **Baseline**
   3. Description: "Clean OS with SSH and Rust installed"
   4. To restore: **Virtual Machine** → **Snapshots** → **Baseline** → **Restore**

   **Tart (macOS) - Automated:**

8. **Deploy Agent Code**:

   The agent build and deployment process involves multiple steps:

   **Build Process:**
   - Code is synced from local machine to VM via SSH/tar
   - Agent is compiled on the target VM using native toolchain
   - Compiled binary is copied back to local machine
   - Binary is deployed to control server binaries directory

   **Manual Build Example (Windows):**
   ```bash
   # Sync code to VM
   cd /path/to/zedr && tar czf - agent/ protocol/ | sshpass -p zedr ssh -p 2222 zedr@localhost 'tar xzf -'
   
   # Build on VM
   sshpass -p zedr ssh -p 2222 zedr@localhost 'cd agent/windows && cargo build --release'
   
   # Copy binary back
   sshpass -p zedr ssh -p 2222 zedr@localhost 'cd agent && tar czf - target/release/zedr-agent-windows.exe' | tar xzf -
   
   # Deploy to control server
   cp agent/target/release/zedr-agent-windows.exe control_server/backend/binaries/v0.1.0/windows/arm64/zedr-agent.exe
   ```

   **Automated via Makefile:**
   - `make test-windows` - Build and test Windows agent
   - `make test-linux` - Build and test Linux agent  
   - `make test-macos` - Build and test macOS agent

   **Binary Deployment Structure:**
   ```
   control_server/backend/binaries/
   ├── v0.1.0/
   │   ├── windows/
   │   │   └── arm64/
   │   │       └── zedr-agent.exe
   │   ├── linux/
   │   │   └── arm64/
   │   │       └── zedr-agent
   │   └── macos/
   │       └── arm64/
   │           └── zedr-agent
   ```

   Built binaries must be placed in the control server's binaries directory to be available for agent installation and upgrades via the web UI.
