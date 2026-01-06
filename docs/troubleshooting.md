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
