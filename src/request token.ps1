# ============================================================
# Microsoft Graph OAuth 2.0 Authorization Code Flow
# 手動複製回調 URL 版本（無需 HttpListener）
# ============================================================

Add-Type -AssemblyName System.Web

# 提示輸入必要參數
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Microsoft Graph OAuth 授權令牌獲取工具" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

$ClientId = Read-Host "請輸入 Client ID"
$TenantId = Read-Host "請輸入 Tenant ID (或輸入 common)"
$ClientSecret = Read-Host "請輸入 Client Secret (公開客戶端可留空)" -AsSecureString
$ClientSecretPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret))

# 回調 URI（必須與應用註冊中配置的一致）
Write-Host "`n常用回調 URI 示例:" -ForegroundColor Yellow
Write-Host "  1. http://localhost" -ForegroundColor Gray
Write-Host "  2. http://localhost:8400/" -ForegroundColor Gray
Write-Host "  3. https://login.microsoftonline.com/common/oauth2/nativeclient" -ForegroundColor Gray
$RedirectUri = Read-Host "`n請輸入 Redirect URI (留空使用 http://localhost)"
if ([string]::IsNullOrWhiteSpace($RedirectUri)) {
    $RedirectUri = "http://localhost"
}

Write-Host "`n使用回調 URI: $RedirectUri" -ForegroundColor Green
Write-Host "請確保應用註冊中已配置此 URI`n" -ForegroundColor Yellow

# 請求的 scope（包含 offline_access 以獲取 refresh_token）
$Scopes = "openid profile offline_access https://graph.microsoft.com/.default"
Write-Host "請求的 Scopes: $Scopes`n" -ForegroundColor Cyan

# ============================================================
# 生成 PKCE Code Verifier 與 Code Challenge
# ============================================================
function New-PKCECodes {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $codeVerifier = [Convert]::ToBase64String($bytes) `
        -replace '\+', '-' -replace '/', '_' -replace '=', ''
    
    $sha256 = [Security.Cryptography.SHA256]::Create()
    $challengeBytes = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($codeVerifier))
    $codeChallenge = [Convert]::ToBase64String($challengeBytes) `
        -replace '\+', '-' -replace '/', '_' -replace '=', ''
    
    return @{
        Verifier = $codeVerifier
        Challenge = $codeChallenge
    }
}

$pkce = New-PKCECodes
Write-Host "已生成 PKCE 驗證碼`n" -ForegroundColor Green

# ============================================================
# 步驟 1：打開瀏覽器進行授權
# ============================================================
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "步驟 1: 打開瀏覽器進行授權" -ForegroundColor Yellow
Write-Host "============================================================`n" -ForegroundColor Yellow

# 構建授權 URL
$state = [Guid]::NewGuid().ToString()
$authUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?" + 
    "client_id=$ClientId" +
    "&response_type=code" +
    "&redirect_uri=$([Uri]::EscapeDataString($RedirectUri))" +
    "&response_mode=query" +
    "&scope=$([Uri]::EscapeDataString($Scopes))" +
    "&state=$state" +
    "&code_challenge=$($pkce.Challenge)" +
    "&code_challenge_method=S256"

Write-Host "即將打開瀏覽器..." -ForegroundColor Cyan
Write-Host "如果瀏覽器未自動打開，請手動複製以下 URL 到瀏覽器：`n" -ForegroundColor Yellow
Write-Host $authUrl -ForegroundColor Gray
Write-Host ""

Start-Sleep -Seconds 2
Start-Process $authUrl

# ============================================================
# 步驟 2：手動輸入回調 URL
# ============================================================
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "步驟 2: 複製授權後的回調 URL" -ForegroundColor Yellow
Write-Host "============================================================`n" -ForegroundColor Yellow

Write-Host "請在瀏覽器中完成登入並授權。" -ForegroundColor Cyan
Write-Host "授權完成後，瀏覽器會跳轉到一個包含授權碼的 URL。`n" -ForegroundColor Cyan
Write-Host "示例 URL 格式:" -ForegroundColor Yellow
Write-Host "  http://localhost?code=0.AX...很長的字串...&state=xxx`n" -ForegroundColor Gray

$CallbackUrl = Read-Host "請完整複製跳轉後的 URL 並貼上"

if ([string]::IsNullOrWhiteSpace($CallbackUrl)) {
    Write-Host "`n錯誤: 未輸入回調 URL" -ForegroundColor Red
    exit
}

# ============================================================
# 步驟 3：解析授權碼
# ============================================================
Write-Host "`n============================================================" -ForegroundColor Yellow
Write-Host "步驟 3: 解析授權碼" -ForegroundColor Yellow
Write-Host "============================================================`n" -ForegroundColor Yellow

try {
    # 解析 URL
    $uri = [Uri]$CallbackUrl
    $queryParams = [System.Web.HttpUtility]::ParseQueryString($uri.Query)
    
    $code = $queryParams["code"]
    $returnedState = $queryParams["state"]
    $errorAuth = $queryParams["error"]
    $errorDescription = $queryParams["error_description"]
    
    if ($errorAuth) {
        Write-Host "授權失敗:" -ForegroundColor Red
        Write-Host "  錯誤: $errorAuth" -ForegroundColor Red
        Write-Host "  描述: $errorDescription" -ForegroundColor Red
        exit
    }
    
    if (-not $code) {
        Write-Host "錯誤: 未在 URL 中找到授權碼 (code 參數)" -ForegroundColor Red
        Write-Host "請確保複製了完整的回調 URL" -ForegroundColor Red
        exit
    }
    
    if ($returnedState -ne $state) {
        Write-Host "警告: State 參數不匹配，可能存在安全風險" -ForegroundColor Yellow
        $continue = Read-Host "是否繼續? (y/n)"
        if ($continue -ne 'y') {
            exit
        }
    }
    
    Write-Host "✓ 授權碼已成功提取: $($code.Substring(0, [Math]::Min(30, $code.Length)))..." -ForegroundColor Green
    
} catch {
    Write-Host "`n錯誤: 無法解析回調 URL" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit
}

# ============================================================
# 步驟 4：用授權碼換取 Access Token 和 Refresh Token
# ============================================================
Write-Host "`n============================================================" -ForegroundColor Yellow
Write-Host "步驟 4: 使用授權碼換取令牌" -ForegroundColor Yellow
Write-Host "============================================================`n" -ForegroundColor Yellow

$tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$tokenBody = @{
    client_id     = $ClientId
    grant_type    = "authorization_code"
    code          = $code
    redirect_uri  = $RedirectUri
    code_verifier = $pkce.Verifier
}

# 如果提供了 Client Secret，添加到請求中
if ($ClientSecretPlain) {
    $tokenBody["client_secret"] = $ClientSecretPlain
}

try {
    Write-Host "正在請求令牌..." -ForegroundColor Cyan
    $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
    
    Write-Host "`n============================================================" -ForegroundColor Green
    Write-Host "令牌獲取成功！" -ForegroundColor Green
    Write-Host "============================================================`n" -ForegroundColor Green
    
    Write-Host "Access Token (前50字符):" -ForegroundColor Cyan
    Write-Host $tokenResponse.access_token.Substring(0, [Math]::Min(50, $tokenResponse.access_token.Length)) -ForegroundColor Yellow
    
    Write-Host "`nRefresh Token:" -ForegroundColor Cyan
    Write-Host $tokenResponse.refresh_token -ForegroundColor Yellow
    
    Write-Host "`nToken 類型: $($tokenResponse.token_type)" -ForegroundColor Cyan
    Write-Host "有效期: $($tokenResponse.expires_in) 秒" -ForegroundColor Cyan
    
    if ($tokenResponse.scope) {
        Write-Host "授予的 Scopes: $($tokenResponse.scope)" -ForegroundColor Cyan
    }
    
    # 保存到 JSON 文件
    $outputPath = ".\tokens_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $tokenResponse | ConvertTo-Json | Out-File -FilePath $outputPath -Encoding UTF8
    Write-Host "`n令牌已保存到: $outputPath" -ForegroundColor Green
    
    # ============================================================
    # 步驟 5：測試 Access Token
    # ============================================================
    Write-Host "`n============================================================" -ForegroundColor Yellow
    Write-Host "步驟 5: 測試訪問 Microsoft Graph" -ForegroundColor Yellow
    Write-Host "============================================================`n" -ForegroundColor Yellow
    
    $headers = @{
        Authorization = "Bearer $($tokenResponse.access_token)"
    }
    
    try {
        $meResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers
        Write-Host "✓ 成功獲取用戶信息:" -ForegroundColor Green
        Write-Host "  顯示名稱: $($meResponse.displayName)" -ForegroundColor Cyan
        Write-Host "  用戶主體名稱: $($meResponse.userPrincipalName)" -ForegroundColor Cyan
        Write-Host "  郵件: $($meResponse.mail)" -ForegroundColor Cyan
    } catch {
        Write-Host "警告: 無法測試 /me 端點" -ForegroundColor Yellow
        Write-Host $_.Exception.Message -ForegroundColor Yellow
    }
    
    # ============================================================
    # 輸出 Config.json 格式
    # ============================================================
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host "Config.json 格式（複製到應用配置中）:" -ForegroundColor Cyan
    Write-Host "============================================================`n" -ForegroundColor Cyan
    
    $configTemplate = @"
{
  "ClientId": "$ClientId",
  "ClientSecret": "$ClientSecretPlain",
  "RefreshToken": "$($tokenResponse.refresh_token)"
}
"@
    
    Write-Host $configTemplate -ForegroundColor Yellow
    
    # 複製到剪貼板（如果支持）
    try {
        $configTemplate | Set-Clipboard
        Write-Host "`n✓ 配置已複製到剪貼板" -ForegroundColor Green
    } catch {
        Write-Host "`n提示: 無法自動複製到剪貼板，請手動複製上方內容" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "`n令牌獲取失敗:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    if ($_.ErrorDetails.Message) {
        $errorDetail = $_.ErrorDetails.Message | ConvertFrom-Json
        Write-Host "  錯誤代碼: $($errorDetail.error)" -ForegroundColor Red
        Write-Host "  描述: $($errorDetail.error_description)" -ForegroundColor Red
    }
}

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "腳本執行完成！" -ForegroundColor Green
Write-Host "============================================================`n" -ForegroundColor Green
