# Troubleshooting

Solutions to common issues with Zebbern-MCP.

---

## Quick Diagnostics

Run these commands to quickly identify issues:

### Check Kali API Status
```bash
curl http://YOUR_KALI_IP:5000/health
```

### Check Service Status
```bash
sudo systemctl status kali-mcp
```

### View Recent Logs
```bash
sudo journalctl -u kali-mcp -n 50
```

---

## Connection Issues

### Cannot Connect to Kali API

!!! bug "Error: Connection refused"

    **Symptoms:**
    - MCP tools return connection errors
    - `curl` to API fails

    **Solutions:**

    1. **Check if service is running:**
       ```bash
       sudo systemctl status kali-mcp
       ```

    2. **Start the service:**
       ```bash
       sudo systemctl start kali-mcp
       ```

    3. **Check if port is open:**
       ```bash
       netstat -tlnp | grep 5000
       ```

    4. **Check firewall:**
       ```bash
       sudo ufw status
       sudo ufw allow 5000/tcp
       ```

    5. **Verify IP address:**
       ```bash
       ip addr show
       ```

---

### Timeout Errors

!!! bug "Error: Request timed out"

    **Symptoms:**
    - Long-running scans fail
    - "Timeout" errors in responses

    **Solutions:**

    1. **Increase client timeout:**
       ```bash
       python mcp_server.py --timeout 900
       ```

    2. **Or in VS Code config:**
       ```json
       {
         "args": ["mcp_server.py", "--timeout", "900"]
       }
       ```

    3. **Check server-side timeout** in `config.py`:
       ```python
       COMMAND_TIMEOUT = 900
       ```

---

### MCP Server Won't Start

!!! bug "VS Code shows MCP server failed"

    **Symptoms:**
    - Red indicator in VS Code
    - No MCP tools available

    **Solutions:**

    1. **Check Python path:**
       ```bash
       which python
       # or on Windows
       where python
       ```

    2. **Verify mcp_server.py location:**
       ```bash
       ls -la /path/to/mcp_server.py
       ```

    3. **Test manually:**
       ```bash
       python mcp_server.py --debug
       ```

    4. **Check dependencies:**
       ```bash
       pip install mcp requests
       ```

---

## Tool Issues

### Tool Not Found

!!! bug "Error: nuclei binary not found"

    **Symptoms:**
    - Health check shows tool as `false`
    - Tool commands fail

    **Solutions:**

    1. **Check health endpoint:**
       ```bash
       curl http://KALI_IP:5000/health | jq .tools_status
       ```

    2. **Install missing Go tools:**
       ```bash
       go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
       ```

    3. **Create symlinks:**
       ```bash
       sudo ln -sf ~/go/bin/nuclei /usr/local/bin/
       ```

    4. **Check PATH:**
       ```bash
       echo $PATH
       # Should include ~/go/bin
       ```

---

### Tool Crashes or Hangs

!!! bug "Tool execution hangs indefinitely"

    **Symptoms:**
    - Command never returns
    - CPU usage high

    **Solutions:**

    1. **Check for interactive prompts:**
       Some tools wait for input. Use non-interactive flags:
       ```
       sqlmap --batch
       nuclei -silent
       ```

    2. **Set timeout limits:**
       ```json
       {"additional_args": "--timeout 60"}
       ```

    3. **Check system resources:**
       ```bash
       top
       free -m
       ```

---

## Stuck Commands & Process Management (Docker)

When the AI runs a command via `zebbern_exec` or `exec_stream` and it hangs
(zombie process, listening socket, crashed tool), the AI has no sense of time —
it will wait until the timeout (up to 1 hour). **You** have to intervene.

### How to spot a stuck command

- The VS Code tool call shows a spinner with no new output
- The "Output" panel for the MCP tool stays empty or stopped updating
- You know the command should have finished by now

### Step 1: See what's running inside the container

Open a **PowerShell / terminal** (not the AI chat) and run:

```powershell
# List all processes sorted by start time (newest first)
docker exec zebbern-kali ps aux --sort=-start_time | head -30
```

```powershell
# Or filter to just your suspected stuck process
docker exec zebbern-kali ps aux | findstr "python3\|nmap\|ffuf\|nc\|listen"
```

```powershell
# See how long each process has been running (ELAPSED column)
docker exec zebbern-kali ps -eo pid,etime,cmd --sort=-etime | head -20
```

```powershell
# Check which process is holding a specific port
docker exec zebbern-kali ss -tlnp | findstr "9100"
```

### Step 2: Kill the stuck process

**Option A — Direct kill (no message to AI):**

```powershell
# Kill by PID (replace 1229 with the actual PID from step 1)
docker exec zebbern-kali kill -9 1229
```

**Option B — Kill via API with a message the AI reads:**

The `/api/kill/<pid>` endpoint kills the process AND injects your message
directly into the command result. The AI sees your message as part of the
tool output — no need to type anything in the chat window.

```powershell
# Kill PID 1229 and tell the AI to use port 9101 instead
curl "http://localhost:5000/api/kill/1229?message=port+stuck+use+9101"
```

```powershell
# Kill with a longer message
curl "http://localhost:5000/api/kill/1229?message=zombie+process+skip+this+step"
```

The killed command's response will include:
```json
{ "user_killed": true, "user_message": "port stuck use 9101", ... }
```

The AI reads `user_message` and adjusts its next step accordingly.

**Other kill patterns:**

```powershell
# Kill by name pattern (e.g. all python3 listeners)
docker exec zebbern-kali pkill -9 -f "ct_listen"
```

```powershell
# Kill everything matching a pattern (be careful)
docker exec zebbern-kali pkill -9 -f "nc -l"
```

```powershell
# Nuclear option: kill ALL user commands (leaves Flask server running)
docker exec zebbern-kali pkill -9 -f "^(?!.*kali_server).*python3"
```

### Step 3: Communicate the result back to the AI

After you kill the process, one of two things happens:

**A) The MCP tool call returns automatically.**
When you kill the subprocess inside Docker, Flask detects the process died and
returns the partial output + a non-zero exit code. The AI reads this result and
sees the command was killed. You can then type a follow-up message to give context:

> *"That command was stuck on port 9100 — the port was held by a zombie.
> Use port 9101 instead."*

The AI will incorporate your message and adjust.

**B) The MCP tool call is still spinning (SSE stream didn't close).**
Click the **Cancel** / **Stop** button on the tool call in VS Code. The AI receives
`Cancelled` as the result. Then type your explanation:

> *"I cancelled that — the nc listener was stuck. Skip that step and
> move on to submitting the flag."*

> *"Killed PID 1229 because it was a zombie holding port 9100.
> Re-run the same command but on port 9101."*

The AI reads your message as its next instruction and continues accordingly.
You are effectively **steering the AI** by choosing when to kill and what to say.

### Step 4: Clean up zombie ports (optional)

If a port is stuck in TIME_WAIT after killing a process:

```powershell
# Check socket state
docker exec zebbern-kali ss -tlnp | findstr "TIME_WAIT\|LISTEN"
```

TIME_WAIT sockets clear automatically after 60 seconds. If you can't wait,
just use a different port — tell the AI which one.

### Quick Reference Card

| What you want | Command |
|---|---|
| List processes | `docker exec zebbern-kali ps aux --sort=-start_time \| head 20` |
| Process runtime | `docker exec zebbern-kali ps -eo pid,etime,cmd --sort=-etime \| head 20` |
| Who holds a port | `docker exec zebbern-kali ss -tlnp` |
| Kill by PID | `docker exec zebbern-kali kill -9 <PID>` |
| Kill + message to AI | `curl "http://localhost:5000/api/kill/<PID>?message=your+note"` |
| List processes (API) | `curl http://localhost:5000/api/ps` |
| Kill by name | `docker exec zebbern-kali pkill -9 -f "<pattern>"` |
| Container resource usage | `docker stats zebbern-kali --no-stream` |
| Container logs (Flask) | `docker logs zebbern-kali --tail 50` |
| Restart entire container | `docker restart zebbern-kali` |

### PowerShell Aliases (optional)

Add these to your PowerShell profile (`$PROFILE`) for quick access:

```powershell
function kali-ps    { docker exec zebbern-kali ps aux --sort=-start_time | head -20 }
function kali-ports { docker exec zebbern-kali ss -tlnp }
function kali-top   { docker exec zebbern-kali top -b -n 1 | head -25 }
function kali-kill  {
    param([int]$pid, [string]$msg="")
    if ($msg) {
        $encoded = [System.Uri]::EscapeDataString($msg)
        Invoke-RestMethod "http://localhost:5000/api/kill/$pid`?message=$encoded"
    } else {
        docker exec zebbern-kali kill -9 $pid
        Write-Host "Killed PID $pid"
    }
}
function kali-pkill { param([string]$pat) docker exec zebbern-kali pkill -9 -f $pat; Write-Host "Killed pattern: $pat" }
function kali-logs  { docker logs zebbern-kali --tail 50 }
```

Then just:
```powershell
kali-ps                                    # see processes
kali-kill 1229                             # kill stuck PID (direct)
kali-kill 1229 "port stuck, use 9101"      # kill + inject message for AI
kali-pkill "nc -l"                         # kill all netcat listeners
kali-ports                                 # check port bindings
```

---

### Metasploit Issues

!!! bug "Metasploit database not running"

    **Symptoms:**
    - Metasploit commands fail
    - "Database not connected" errors

    **Solutions:**

    1. **Initialize database:**
       ```bash
       sudo msfdb init
       ```

    2. **Start PostgreSQL:**
       ```bash
       sudo systemctl start postgresql
       ```

    3. **Verify database:**
       ```bash
       msfconsole -q -x "db_status; exit"
       ```

---

## Installation Issues

### Python Version Error

!!! bug "Python 3.10+ required"

    **Solutions:**

    1. **Check Python version:**
       ```bash
       python3 --version
       ```

    2. **Install newer Python:**
       ```bash
       sudo apt install python3.11 python3.11-venv
       ```

    3. **Use pyenv:**
       ```bash
       curl https://pyenv.run | bash
       pyenv install 3.11.0
       pyenv global 3.11.0
       ```

---

### Go Tools Installation Fails

!!! bug "Go install fails"

    **Symptoms:**
    - `go install` command fails
    - Tools not in ~/go/bin

    **Solutions:**

    1. **Check Go installation:**
       ```bash
       go version
       ```

    2. **Install Go:**
       ```bash
       sudo apt install golang-go
       ```

    3. **Set GOPATH:**
       ```bash
       export GOPATH=$HOME/go
       export PATH=$PATH:$GOPATH/bin
       ```

    4. **Install tool manually:**
       ```bash
       go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
       ```

---

### Service Won't Start

!!! bug "systemctl start kali-mcp fails"

    **Solutions:**

    1. **Check logs:**
       ```bash
       sudo journalctl -u kali-mcp -n 100
       ```

    2. **Verify paths in service file:**
       ```bash
       cat /etc/systemd/system/kali-mcp.service
       ```

    3. **Test manually:**
       ```bash
       cd /opt/zebbern-kali/zebbern-kali
       /opt/zebbern-kali/venv/bin/python kali_server.py
       ```

    4. **Check permissions:**
       ```bash
       ls -la /opt/zebbern-kali/
       ```

    5. **Reload systemd:**
       ```bash
       sudo systemctl daemon-reload
       sudo systemctl restart kali-mcp
       ```

---

## API Errors

### 500 Internal Server Error

!!! bug "API returns 500 error"

    **Solutions:**

    1. **Check server logs:**
       ```bash
       sudo journalctl -u kali-mcp -f
       ```

    2. **Look for Python tracebacks:**
       ```bash
       sudo journalctl -u kali-mcp -n 100 | grep -A 10 "Traceback"
       ```

    3. **Common causes:**
       - Missing dependencies
       - File permission issues
       - Database errors

---

### 400 Bad Request

!!! bug "Missing required parameter"

    **Symptoms:**
    - API returns 400
    - "parameter is required" error

    **Solutions:**

    1. **Check required parameters:**
       See [API Reference](api-reference.md) for each endpoint.

    2. **Validate JSON format:**
       ```bash
       echo '{"target": "192.168.1.1"}' | jq .
       ```

---

## SSH Session Issues

### SSH Connection Fails

!!! bug "SSH connection refused"

    **Solutions:**

    1. **Verify target SSH is running:**
       ```bash
       nmap -p 22 TARGET_IP
       ```

    2. **Check credentials:**
       - Verify username/password
       - Check SSH key permissions (600)

    3. **Test manual connection:**
       ```bash
       ssh user@TARGET_IP
       ```

---

### SFTP Upload/Download Fails

!!! bug "SFTP operation failed"

    **Solutions:**

    1. **Check file permissions:**
       ```bash
       ls -la /path/to/file
       ```

    2. **Verify remote path exists:**
       ```bash
       ssh user@host "ls -la /remote/path/"
       ```

    3. **Check disk space:**
       ```bash
       df -h
       ```

---

## Performance Issues

### Slow API Responses

**Solutions:**

1. **Check system resources:**
   ```bash
   top
   free -m
   df -h
   ```

2. **Reduce concurrent scans:**
   Run one tool at a time.

3. **Increase VM resources:**
   - Add more RAM (4GB+)
   - Add more CPU cores

4. **Use faster wordlists:**
   ```
   /usr/share/wordlists/dirb/common.txt  # Fast
   /usr/share/wordlists/rockyou.txt       # Slow
   ```

---

### High Memory Usage

**Solutions:**

1. **Check running processes:**
   ```bash
   ps aux --sort=-%mem | head -20
   ```

2. **Kill zombie processes:**
   ```bash
   pkill -9 nmap  # Example
   ```

3. **Restart service:**
   ```bash
   sudo systemctl restart kali-mcp
   ```

---

## Database Issues

### Database Locked

!!! bug "SQLite database is locked"

    **Solutions:**

    1. **Stop conflicting processes:**
       ```bash
       lsof /opt/zebbern-kali/database/pentest.db
       ```

    2. **Restart service:**
       ```bash
       sudo systemctl restart kali-mcp
       ```

---

### Database Corrupt

!!! bug "Database malformed"

    **Solutions:**

    1. **Backup current database:**
       ```bash
       cp pentest.db pentest.db.backup
       ```

    2. **Try to repair:**
       ```bash
       sqlite3 pentest.db "PRAGMA integrity_check;"
       ```

    3. **Reset database (lose data):**
       ```bash
       rm pentest.db
       # Will be recreated automatically
       ```

---

## Logging & Debugging

### Enable Debug Mode

**Client:**
```bash
python mcp_server.py --debug
```

**Server:**
Set in environment:
```bash
export DEBUG_MODE=1
sudo systemctl restart kali-mcp
```

### Useful Log Commands

```bash
# Follow logs in real-time
sudo journalctl -u kali-mcp -f

# Last 100 lines
sudo journalctl -u kali-mcp -n 100

# Logs since boot
sudo journalctl -u kali-mcp -b

# Logs from last hour
sudo journalctl -u kali-mcp --since "1 hour ago"

# Search for errors
sudo journalctl -u kali-mcp | grep -i error
```

---

## VPN & SOCKS Proxy Issues

### VPN Connect Fails

!!! bug "VPN connection error"

    **Solutions:**

    1. **Check Docker capabilities:**
       The container needs `NET_ADMIN`, `NET_RAW`, and access to `/dev/net/tun`:
       ```yaml
       cap_add:
         - NET_RAW
         - NET_ADMIN
       devices:
         - /dev/net/tun:/dev/net/tun
       ```

    2. **Verify config file is mounted:**
       ```bash
       docker exec kali-mcp ls /vpn/
       ```

    3. **Check VPN_DIR in docker-compose.yml:**
       ```yaml
       volumes:
         - ${VPN_DIR}:/vpn:ro
       ```

### SOCKS Proxy Not Working

!!! bug "Cannot connect to SOCKS proxy on port 1080"

    **Solutions:**

    1. **Check if VPN is connected first** — the proxy only starts when a VPN is active:
       ```bash
       curl http://localhost:5000/api/vpn/status
       ```

    2. **Verify port 1080 is exposed in docker-compose.yml:**
       ```yaml
       ports:
         - "1080:1080"
       ```

    3. **Check microsocks process inside container:**
       ```bash
       docker exec kali-mcp pgrep -a microsocks
       ```

---

## Getting Help

If you can't resolve your issue:

1. **Check existing issues:**
   [GitHub Issues](https://github.com/zebbern/zebbern-mcp/issues)

2. **Collect diagnostic info:**
   ```bash
   # System info
   uname -a
   python3 --version
   go version

   # Service status
   sudo systemctl status kali-mcp

   # Recent logs
   sudo journalctl -u kali-mcp -n 100

   # Health check
   curl http://localhost:5000/health
   ```

3. **Open a new issue** with:
   - Clear problem description
   - Steps to reproduce
   - Error messages
   - Diagnostic info above
