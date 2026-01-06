# Sync local changes to Kali VM and restart the server
$KALI_IP = "192.168.44.131"
$KALI_USER = "kali"
$KALI_PASS = "kali"
$REMOTE_PATH = "/opt/zebbern-kali"
$LOCAL_PATH = $PSScriptRoot

Write-Host "🔄 Syncing to Kali VM at $KALI_IP..." -ForegroundColor Cyan

# Sync zebbern-kali folder
Write-Host "📁 Syncing zebbern-kali..." -ForegroundColor Yellow
scp -r -o StrictHostKeyChecking=no "$LOCAL_PATH\zebbern-kali\*" "${KALI_USER}@${KALI_IP}:${REMOTE_PATH}/"

# Restart the service
Write-Host "🔃 Restarting kali-mcp service..." -ForegroundColor Yellow
ssh -o StrictHostKeyChecking=no "${KALI_USER}@${KALI_IP}" "echo 'kali' | sudo -S systemctl restart kali-mcp"

# Check status
Write-Host "✅ Checking service status..." -ForegroundColor Green
ssh -o StrictHostKeyChecking=no "${KALI_USER}@${KALI_IP}" "echo 'kali' | sudo -S systemctl status kali-mcp --no-pager -l | head -15"

Write-Host "`n🎉 Sync complete!" -ForegroundColor Green
