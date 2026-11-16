# Agent installation via CLI

The flow of clean-slate testing an agent is doable automatically via cli:

## Database Reset

```bash
make clean-db
```

## VM Cleanup

```bash
# Complete Windows VM cleanup - removes all zedr services, binaries, logs, and verifies clean state
make clean-vm-windows
```

This command:
- Stops and deletes ALL zedr services (including staging variants)
- Terminates all zedr processes
- Removes all installation directories (C:\Program Files\zedr, C:\ProgramData\zedr)
- Removes build directory (C:\zedr)
- Cleans registry entries
- Clears temp files
- **Verifies** nothing zedr-related remains (0 services, 0 processes, 0 directories)

## Build Agent Binary

```bash
# Build Windows agent (includes comprehensive VM cleanup with artifact enumeration, latest code sync, build, and binary retrieval)
make build-windows-binary
```

## Full End-to-End Test

```bash
# Complete installation test (database reset + build + install + verify)
make test-agent-install-windows

# Or run steps manually:
make clean-db                                    # Database reset
make clean-vm-windows                            # VM cleanup with verification
make build-windows-binary                        # Build (includes VM cleanup)
make test-install-windows-through-control-server # Install
```

## Testing Steps Breakdown

### 1. Build and Copy Binary

- `make build-windows-binary` handles: Comprehensive VM cleanup (services enumeration, event logs, registry, processes, temp files), latest code sync, build, and binary copy to `control_server/backend/binaries/v0.1.0/windows/arm64/zedr-agent.exe`

### 2. Install via Control Server

- `make test-install-windows-through-control-server` handles: server startup, authentication, install key generation, installation command execution, and verification

## Manual Steps (if needed)

- Admin credentials are at `./../../secrets/.env.server.local`
- Don't workaround using standard APIs to perform actions
- Fix any issues at the source code level rather than using temporary fixes or manual bypasses

## Upgrade Testing

### Test Agent Upgrade Flow

```bash
# 1. Ensure agent is installed and running
make test-install-windows-through-control-server

# 2. Login and get JWT token
TOKEN=$(curl -k --http1.1 -s -X POST https://localhost:7770/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin-pass-change-in-production-min-8-chars"}' | jq -r '.token')

# 3. Get agent ID
AGENT_ID=$(curl -k --http1.1 -s -H "Authorization: Bearer $TOKEN" \
  https://localhost:7770/api/admin/agents | jq -r '.agents[0].id')
echo "Agent ID: $AGENT_ID"

# 4. Generate fresh install key (required by API for tracking)
curl -k --http1.1 -s -X POST https://localhost:7770/api/admin/installers/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_version":"0.1.0"}' | jq

# 5. Get the unused install key ID
INSTALL_KEY_ID=$(sqlite3 control_server/backend/zedr.db \
  "SELECT id FROM install_keys WHERE used_at IS NULL ORDER BY created_at DESC LIMIT 1;")
echo "Install Key ID: $INSTALL_KEY_ID"

# 6. Issue upgrade command via API
curl -k --http1.1 -X POST https://localhost:7770/api/admin/upgrades \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\":\"$AGENT_ID\",\"install_key_id\":\"$INSTALL_KEY_ID\",\"target_version\":\"0.1.0\"}" | jq

# 7. Monitor upgrade progress (wait ~30s for next heartbeat)
sleep 35
sshpass -p zedr ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -p 2222 zedr@localhost 'powershell -Command "Get-Content C:\Windows\Temp\zedr-agent.log -Tail 50"'

# 8. Verify upgrade completed via API
curl -k --http1.1 -s -H "Authorization: Bearer $TOKEN" "https://localhost:7770/api/admin/upgrades" | jq '.[] | select(.agent_id == "'$AGENT_ID'") | {status, target_version}'
```

Expected upgrade flow:
1. Agent receives upgrade command via heartbeat
2. Downloads binary using agent_id authentication (no install key)
3. Creates staging service with proper arguments
4. Staging service validates signature and connectivity
5. Stops main service and replaces binary
6. Starts new service and re-registers
7. Sends completion event and cleans up

### Verification Checklist

After upgrade completes, verify using APIs:
- [ ] Upgrade command status = 'completed': `curl -k --http1.1 -s -H "Authorization: Bearer $TOKEN" https://localhost:7770/api/admin/upgrades | jq`
- [ ] Agent status = 'online': `curl -k --http1.1 -s -H "Authorization: Bearer $TOKEN" https://localhost:7770/api/admin/agents | jq`
- [ ] Main service (zedr-agent) running with StartType Automatic
- [ ] Staging service (zedr-agent-staging) stopped with StartType Manual
- [ ] No errors in agent logs at `C:\Windows\Temp\zedr-agent.log`

### Cleanup Between Tests

```bash
# 1. Stop and remove services on VM
sshpass -p zedr ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -p 2222 zedr@localhost 'powershell -Command "Stop-Service zedr-agent,zedr-agent-staging -ErrorAction SilentlyContinue; sc.exe delete zedr-agent; sc.exe delete zedr-agent-staging; Remove-Item -Force -ErrorAction SilentlyContinue C:\\Windows\\Temp\\zedr-agent.log,C:\\Windows\\Temp\\zedr-agent-staging.log,C:\\zedr-agent.exe"'

# 2. Clean database via API (stop and restart backend to flush)
cd control_server && pm2 stop zedr-backend
sqlite3 backend/zedr.db "DELETE FROM events; DELETE FROM upgrade_commands; DELETE FROM agents; DELETE FROM install_keys;"
pm2 start zedr-backend
cd ..

# 3. Verify clean state
sshpass -p zedr ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -p 2222 zedr@localhost 'powershell -Command "Get-Service zedr* 2>$null"'
# Should return no services

curl -k --http1.1 -s -u admin:admin-pass-change-in-production-min-8-chars https://localhost:7770/api/admin/agents | jq '.agents | length'
# Should return 0
```

### Common Issues

**HTTP/1.1 Requirement:**
- All curl commands must use `--http1.1` flag
- Server only advertises HTTP/1.1 in ALPN for minreq compatibility
- Without `--http1.1`, curl defaults to HTTP/2 and may encounter connection issues

**Self-Signed Certificate:**
- All HTTPS requests require `-k` flag to skip certificate verification
- Certificate is trusted in macOS keychain for browser access
- Agent uses native TLS (SChannel on Windows) which validates the trusted certificate

**Stale Binaries:**
- Check for multiple binaries: `find control_server/backend/binaries -name "*.exe"`
- Should only exist in architecture subdirectories: `binaries/v0.1.0/windows/arm64/zedr-agent.exe`
- Makefile automatically removes old binaries before copying new builds

**Environment Variables:**
- Backend needs `ADMIN_PASSWORD` and `ZEDR_SERVER_URL` from `.env.server.local`
- Makefile `dev` target exports these before starting PM2
- Don't rely on PM2's env_file - it doesn't work with cargo spawned processes

**Staging Service:**
- Must receive arguments: `--from-version`, `--to-version`, `--old-service`, `--primary-binary`
- Fixed in service.rs by passing arguments to `service.start()` call
- Check logs at `C:\Windows\Temp\zedr-agent.log` for details

**Agent ID Reusability:**
- Agent ID (from Windows Machine GUID) is persistent credential
- Can be reused for multiple upgrades (tested successfully)
- Unlike install keys which are single-use

## Notes:

- `test-install-windows-through-control-server` also demonstrates how we are getting a token
- when clean state is achieved, stop to verify all data is really cleaned
