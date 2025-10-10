# ============================================================
# Microsoft Graph OAuth 2.0 Authorization Code Flow
# Manual callback URL version (no HttpListener required)
# Supports Traditional Chinese, Japanese, and English
# ============================================================

Add-Type -AssemblyName System.Web

# ============================================================
# Multi-language Support Configuration
# ============================================================
function Get-SystemLanguage {
    $culture = [System.Globalization.CultureInfo]::CurrentUICulture.Name
    
    # Simplified Chinese -> Traditional Chinese
    if ($culture -match '^zh-(CN|SG)') {
        return 'zh-TW'
    }
    # Traditional Chinese
    elseif ($culture -match '^zh-(TW|HK|MO)') {
        return 'zh-TW'
    }
    # Japanese
    elseif ($culture -match '^ja') {
        return 'ja-JP'
    }
    # Default to English
    else {
        return 'en-US'
    }
}

function Get-LocalizedText {
    param([string]$key)
    
    $lang = Get-SystemLanguage
    
    $messages = @{
        'en-US' = @{
            'Title' = 'Microsoft Graph OAuth Token Acquisition Tool'
            'InputClientId' = 'Enter Client ID'
            'InputTenantId' = 'Enter Tenant ID (or "common")'
            'InputClientSecret' = 'Enter Client Secret (leave empty for public client)'
            'RedirectUriExamples' = 'Common Redirect URI examples:'
            'InputRedirectUri' = 'Enter Redirect URI (leave empty to use http://localhost)'
            'UsingRedirectUri' = 'Using Redirect URI: {0}'
            'EnsureUriConfigured' = 'Ensure this URI is configured in your app registration'
            'RequestedScopes' = 'Requested Scopes: {0}'
            'PkceGenerated' = 'PKCE codes generated'
            'Step1' = 'Step 1: Open browser for authorization'
            'Step2' = 'Step 2: Copy callback URL after authorization'
            'Step3' = 'Step 3: Parse authorization code'
            'Step4' = 'Step 4: Exchange authorization code for tokens'
            'Step5' = 'Step 5: Test Microsoft Graph access'
            'OpeningBrowser' = 'Opening browser...'
            'ManualUrl' = 'If browser does not open automatically, copy this URL manually:'
            'CompleteLogin' = 'Complete login and authorization in the browser.'
            'AfterAuth' = 'After authorization, browser will redirect to a URL containing the authorization code.'
            'UrlExample' = 'Example URL format:'
            'PasteUrl' = 'Paste the complete redirected URL here'
            'ErrorNoUrl' = 'Error: No callback URL provided'
            'AuthFailed' = 'Authorization failed:'
            'ErrorLabel' = 'Error:'
            'DescriptionLabel' = 'Description:'
            'ErrorNoCode' = 'Error: Authorization code (code parameter) not found in URL'
            'EnsureCompleteUrl' = 'Ensure the complete callback URL was copied'
            'StateWarning' = 'Warning: State parameter mismatch, possible security risk'
            'Continue' = 'Continue? (y/n)'
            'CodeExtracted' = 'Authorization code successfully extracted: {0}...'
            'RequestingToken' = 'Requesting tokens...'
            'TokenSuccess' = 'Token acquisition successful!'
            'AccessTokenLabel' = 'Access Token (first 50 chars):'
            'RefreshTokenLabel' = 'Refresh Token:'
            'TokenType' = 'Token Type: {0}'
            'ExpiresIn' = 'Expires In: {0} seconds'
            'GrantedScopes' = 'Granted Scopes: {0}'
            'TokensSaved' = 'Tokens saved to: {0}'
            'AccountSaved' = 'Account configuration saved to: {0}'
            'TestingGraph' = 'Testing Microsoft Graph access...'
            'UserInfoSuccess' = 'Successfully retrieved user information:'
            'DisplayName' = 'Display Name: {0}'
            'UserPrincipalName' = 'User Principal Name: {0}'
            'Mail' = 'Mail: {0}'
            'TestWarning' = 'Warning: Unable to test /me endpoint'
            'ConfigFormat' = 'Config.json format (copy to application configuration):'
            'CopiedToClipboard' = 'Configuration copied to clipboard'
            'ManualCopy' = 'Note: Unable to copy to clipboard automatically, please copy manually'
            'TokenFailed' = 'Token acquisition failed:'
            'ErrorCode' = 'Error Code: {0}'
            'ScriptComplete' = 'Script execution complete!'
            'ErrorParsing' = 'Error: Unable to parse callback URL'
        }
        'zh-TW' = @{
            'Title' = 'Microsoft Graph OAuth 授權令牌獲取工具'
            'InputClientId' = '請輸入 Client ID'
            'InputTenantId' = '請輸入 Tenant ID (或輸入 common)'
            'InputClientSecret' = '請輸入 Client Secret (公開客戶端可留空)'
            'RedirectUriExamples' = '常用回調 URI 示例:'
            'InputRedirectUri' = '請輸入 Redirect URI (留空使用 http://localhost)'
            'UsingRedirectUri' = '使用回調 URI: {0}'
            'EnsureUriConfigured' = '請確保應用註冊中已配置此 URI'
            'RequestedScopes' = '請求的 Scopes: {0}'
            'PkceGenerated' = '已生成 PKCE 驗證碼'
            'Step1' = '步驟 1: 打開瀏覽器進行授權'
            'Step2' = '步驟 2: 複製授權後的回調 URL'
            'Step3' = '步驟 3: 解析授權碼'
            'Step4' = '步驟 4: 使用授權碼換取令牌'
            'Step5' = '步驟 5: 測試訪問 Microsoft Graph'
            'OpeningBrowser' = '即將打開瀏覽器...'
            'ManualUrl' = '如果瀏覽器未自動打開,請手動複製以下 URL 到瀏覽器:'
            'CompleteLogin' = '請在瀏覽器中完成登入並授權。'
            'AfterAuth' = '授權完成後,瀏覽器會跳轉到一個包含授權碼的 URL。'
            'UrlExample' = '示例 URL 格式:'
            'PasteUrl' = '請完整複製跳轉後的 URL 並貼上'
            'ErrorNoUrl' = '錯誤: 未輸入回調 URL'
            'AuthFailed' = '授權失敗:'
            'ErrorLabel' = '錯誤:'
            'DescriptionLabel' = '描述:'
            'ErrorNoCode' = '錯誤: 未在 URL 中找到授權碼 (code 參數)'
            'EnsureCompleteUrl' = '請確保複製了完整的回調 URL'
            'StateWarning' = '警告: State 參數不匹配,可能存在安全風險'
            'Continue' = '是否繼續? (y/n)'
            'CodeExtracted' = '✓ 授權碼已成功提取: {0}...'
            'RequestingToken' = '正在請求令牌...'
            'TokenSuccess' = '令牌獲取成功!'
            'AccessTokenLabel' = 'Access Token (前50字符):'
            'RefreshTokenLabel' = 'Refresh Token:'
            'TokenType' = 'Token 類型: {0}'
            'ExpiresIn' = '有效期: {0} 秒'
            'GrantedScopes' = '授予的 Scopes: {0}'
            'TokensSaved' = '令牌已保存到: {0}'
            'AccountSaved' = '帳戶配置已保存到: {0}'
            'TestingGraph' = '正在測試 Microsoft Graph 訪問...'
            'UserInfoSuccess' = '✓ 成功獲取用戶信息:'
            'DisplayName' = '顯示名稱: {0}'
            'UserPrincipalName' = '用戶主體名稱: {0}'
            'Mail' = '郵件: {0}'
            'TestWarning' = '警告: 無法測試 /me 端點'
            'ConfigFormat' = 'Config.json 格式 (複製到應用配置中):'
            'CopiedToClipboard' = '✓ 配置已複製到剪貼板'
            'ManualCopy' = '提示: 無法自動複製到剪貼板,請手動複製上方內容'
            'TokenFailed' = '令牌獲取失敗:'
            'ErrorCode' = '錯誤代碼: {0}'
            'ScriptComplete' = '腳本執行完成!'
            'ErrorParsing' = '錯誤: 無法解析回調 URL'
        }
        'ja-JP' = @{
            'Title' = 'Microsoft Graph OAuth トークン取得ツール'
            'InputClientId' = 'Client ID を入力してください'
            'InputTenantId' = 'Tenant ID を入力してください (または common)'
            'InputClientSecret' = 'Client Secret を入力してください (パブリッククライアントの場合は空白)'
            'RedirectUriExamples' = '一般的なリダイレクト URI の例:'
            'InputRedirectUri' = 'Redirect URI を入力してください (空白の場合 http://localhost を使用)'
            'UsingRedirectUri' = '使用するリダイレクト URI: {0}'
            'EnsureUriConfigured' = 'アプリ登録でこの URI が設定されていることを確認してください'
            'RequestedScopes' = 'リクエストされたスコープ: {0}'
            'PkceGenerated' = 'PKCE コードが生成されました'
            'Step1' = 'ステップ 1: ブラウザで認証を開始'
            'Step2' = 'ステップ 2: 認証後のコールバック URL をコピー'
            'Step3' = 'ステップ 3: 認証コードを解析'
            'Step4' = 'ステップ 4: 認証コードをトークンに交換'
            'Step5' = 'ステップ 5: Microsoft Graph アクセスをテスト'
            'OpeningBrowser' = 'ブラウザを開いています...'
            'ManualUrl' = 'ブラウザが自動的に開かない場合は、この URL を手動でコピーしてください:'
            'CompleteLogin' = 'ブラウザでログインと認証を完了してください。'
            'AfterAuth' = '認証完了後、ブラウザは認証コードを含む URL にリダイレクトされます。'
            'UrlExample' = 'URL 形式の例:'
            'PasteUrl' = 'リダイレクトされた完全な URL を貼り付けてください'
            'ErrorNoUrl' = 'エラー: コールバック URL が入力されていません'
            'AuthFailed' = '認証に失敗しました:'
            'ErrorLabel' = 'エラー:'
            'DescriptionLabel' = '説明:'
            'ErrorNoCode' = 'エラー: URL に認証コード (code パラメータ) が見つかりません'
            'EnsureCompleteUrl' = '完全なコールバック URL がコピーされていることを確認してください'
            'StateWarning' = '警告: State パラメータが一致しません。セキュリティリスクの可能性があります'
            'Continue' = '続行しますか? (y/n)'
            'CodeExtracted' = '✓ 認証コードが正常に抽出されました: {0}...'
            'RequestingToken' = 'トークンをリクエストしています...'
            'TokenSuccess' = 'トークンの取得に成功しました!'
            'AccessTokenLabel' = 'Access Token (最初の50文字):'
            'RefreshTokenLabel' = 'Refresh Token:'
            'TokenType' = 'トークンタイプ: {0}'
            'ExpiresIn' = '有効期限: {0} 秒'
            'GrantedScopes' = '付与されたスコープ: {0}'
            'TokensSaved' = 'トークンが保存されました: {0}'
            'AccountSaved' = 'アカウント設定が保存されました: {0}'
            'TestingGraph' = 'Microsoft Graph アクセスをテストしています...'
            'UserInfoSuccess' = '✓ ユーザー情報の取得に成功しました:'
            'DisplayName' = '表示名: {0}'
            'UserPrincipalName' = 'ユーザープリンシパル名: {0}'
            'Mail' = 'メール: {0}'
            'TestWarning' = '警告: /me エンドポイントをテストできません'
            'ConfigFormat' = 'Config.json 形式 (アプリケーション設定にコピー):'
            'CopiedToClipboard' = '✓ 設定がクリップボードにコピーされました'
            'ManualCopy' = '注意: クリップボードに自動コピーできません。手動でコピーしてください'
            'TokenFailed' = 'トークンの取得に失敗しました:'
            'ErrorCode' = 'エラーコード: {0}'
            'ScriptComplete' = 'スクリプトの実行が完了しました!'
            'ErrorParsing' = 'エラー: コールバック URL を解析できません'
        }
    }
    
    $text = $messages[$lang][$key]
    if ([string]::IsNullOrEmpty($text)) {
        $text = $messages['en-US'][$key]
    }
    return $text
}

function Write-LocalizedHost {
    param(
        [string]$key,
        [string]$color = 'White',
        [object[]]$args = @()
    )
    
    $text = Get-LocalizedText -key $key
    if ($args.Count -gt 0) {
        $text = $text -f $args
    }
    Write-Host $text -ForegroundColor $color
}

# ============================================================
# User Input Section
# ============================================================
Write-Host '============================================================' -ForegroundColor Cyan
Write-LocalizedHost -key 'Title' -color Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

$ClientId = Read-Host (Get-LocalizedText -key 'InputClientId')
$TenantId = Read-Host (Get-LocalizedText -key 'InputTenantId')
$ClientSecret = Read-Host (Get-LocalizedText -key 'InputClientSecret') -AsSecureString
$ClientSecretPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret))

# Redirect URI configuration
Write-Host "`n" -NoNewline
Write-LocalizedHost -key 'RedirectUriExamples' -color Yellow
Write-Host '  1. http://localhost' -ForegroundColor Gray
Write-Host '  2. http://localhost:8400/' -ForegroundColor Gray
Write-Host '  3. https://login.microsoftonline.com/common/oauth2/nativeclient' -ForegroundColor Gray

$RedirectUri = Read-Host "`n$(Get-LocalizedText -key 'InputRedirectUri')"
if ([string]::IsNullOrWhiteSpace($RedirectUri)) {
    $RedirectUri = 'http://localhost'
}

Write-Host "`n" -NoNewline
Write-LocalizedHost -key 'UsingRedirectUri' -color Green -args $RedirectUri
Write-LocalizedHost -key 'EnsureUriConfigured' -color Yellow
Write-Host ''

# Requested scopes (includes offline_access for refresh_token)
$Scopes = 'openid profile offline_access https://graph.microsoft.com/.default'
Write-LocalizedHost -key 'RequestedScopes' -color Cyan -args $Scopes
Write-Host ''

# ============================================================
# PKCE Code Generation (Proof Key for Code Exchange)
# ============================================================
function New-PKCECodes {
    # Generate 32-byte random code verifier
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $codeVerifier = [Convert]::ToBase64String($bytes) `
        -replace '\+', '-' -replace '/', '_' -replace '=', ''
    
    # Generate SHA256 hash for code challenge
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
Write-LocalizedHost -key 'PkceGenerated' -color Green
Write-Host ''

# ============================================================
# Step 1: Open Browser for Authorization
# ============================================================
Write-Host '============================================================' -ForegroundColor Yellow
Write-LocalizedHost -key 'Step1' -color Yellow
Write-Host "============================================================`n" -ForegroundColor Yellow

# Build authorization URL with PKCE
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

Write-LocalizedHost -key 'OpeningBrowser' -color Cyan
Write-LocalizedHost -key 'ManualUrl' -color Yellow
Write-Host ''
Write-Host $authUrl -ForegroundColor Gray
Write-Host ''

Start-Sleep -Seconds 2
Start-Process $authUrl

# ============================================================
# Step 2: Manual Callback URL Input
# ============================================================
Write-Host "`n============================================================" -ForegroundColor Yellow
Write-LocalizedHost -key 'Step2' -color Yellow
Write-Host "============================================================`n" -ForegroundColor Yellow

Write-LocalizedHost -key 'CompleteLogin' -color Cyan
Write-LocalizedHost -key 'AfterAuth' -color Cyan
Write-Host ''
Write-LocalizedHost -key 'UrlExample' -color Yellow
Write-Host '  http://localhost?code=0.AX...very_long_string...&state=xxx' -ForegroundColor Gray
Write-Host ''

$CallbackUrl = Read-Host (Get-LocalizedText -key 'PasteUrl')

if ([string]::IsNullOrWhiteSpace($CallbackUrl)) {
    Write-Host "`n" -NoNewline
    Write-LocalizedHost -key 'ErrorNoUrl' -color Red
    exit 1
}

# ============================================================
# Step 3: Parse Authorization Code
# ============================================================
Write-Host "`n============================================================" -ForegroundColor Yellow
Write-LocalizedHost -key 'Step3' -color Yellow
Write-Host "============================================================`n" -ForegroundColor Yellow

try {
    # Parse callback URL
    $uri = [Uri]$CallbackUrl
    $queryParams = [System.Web.HttpUtility]::ParseQueryString($uri.Query)
    
    $code = $queryParams['code']
    $returnedState = $queryParams['state']
    $errorAuth = $queryParams['error']
    $errorDescription = $queryParams['error_description']
    
    # Check for authorization errors
    if ($errorAuth) {
        Write-LocalizedHost -key 'AuthFailed' -color Red
        Write-Host "  $((Get-LocalizedText -key 'ErrorLabel')) $errorAuth" -ForegroundColor Red
        Write-Host "  $((Get-LocalizedText -key 'DescriptionLabel')) $errorDescription" -ForegroundColor Red
        exit 1
    }
    
    # Verify authorization code exists
    if (-not $code) {
        Write-LocalizedHost -key 'ErrorNoCode' -color Red
        Write-LocalizedHost -key 'EnsureCompleteUrl' -color Red
        exit 1
    }
    
    # Validate state parameter (CSRF protection)
    if ($returnedState -ne $state) {
        Write-LocalizedHost -key 'StateWarning' -color Yellow
        $continue = Read-Host (Get-LocalizedText -key 'Continue')
        if ($continue -ne 'y') {
            exit 1
        }
    }
    
    Write-LocalizedHost -key 'CodeExtracted' -color Green -args $code.Substring(0, [Math]::Min(30, $code.Length))
    
} catch {
    Write-Host "`n" -NoNewline
    Write-LocalizedHost -key 'ErrorParsing' -color Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# ============================================================
# Step 4: Exchange Authorization Code for Tokens
# ============================================================
Write-Host "`n============================================================" -ForegroundColor Yellow
Write-LocalizedHost -key 'Step4' -color Yellow
Write-Host "============================================================`n" -ForegroundColor Yellow

$tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$tokenBody = @{
    client_id     = $ClientId
    grant_type    = 'authorization_code'
    code          = $code
    redirect_uri  = $RedirectUri
    code_verifier = $pkce.Verifier
}

# Add client secret if provided (confidential client)
if ($ClientSecretPlain) {
    $tokenBody['client_secret'] = $ClientSecretPlain
}

try {
    Write-LocalizedHost -key 'RequestingToken' -color Cyan
    $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $tokenBody -ContentType 'application/x-www-form-urlencoded'
    
    Write-Host "`n============================================================" -ForegroundColor Green
    Write-LocalizedHost -key 'TokenSuccess' -color Green
    Write-Host "============================================================`n" -ForegroundColor Green
    
    # Display token information
    Write-LocalizedHost -key 'AccessTokenLabel' -color Cyan
    Write-Host $tokenResponse.access_token.Substring(0, [Math]::Min(50, $tokenResponse.access_token.Length)) -ForegroundColor Yellow
    
    Write-Host "`n" -NoNewline
    Write-LocalizedHost -key 'RefreshTokenLabel' -color Cyan
    Write-Host $tokenResponse.refresh_token -ForegroundColor Yellow
    
    Write-Host "`n" -NoNewline
    Write-LocalizedHost -key 'TokenType' -color Cyan -args $tokenResponse.token_type
    Write-LocalizedHost -key 'ExpiresIn' -color Cyan -args $tokenResponse.expires_in
    
    if ($tokenResponse.scope) {
        Write-LocalizedHost -key 'GrantedScopes' -color Cyan -args $tokenResponse.scope
    }
    
    # ============================================================
    # Save tokens to JSON file (with proper encoding)
    # ============================================================
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $tokensPath = ".\tokens_$timestamp.json"
    
    # Convert to JSON and save (removes extra newlines from tokens)
    $tokenResponse | ConvertTo-Json -Depth 10 | Out-File -FilePath $tokensPath -Encoding UTF8 -NoNewline
    Write-Host "`n" -NoNewline
    Write-LocalizedHost -key 'TokensSaved' -color Green -args $tokensPath

    # Clean refresh token first (before using it)
    $cleanRefreshToken = $tokenResponse.refresh_token.Trim() -replace "`r`n", '' -replace "`n", '' -replace "`r", ''

    # ============================================================
    # Save account configuration (for application use)
    # ============================================================
    $accountPath = ".\account_$timestamp.json"
    $accountConfig = @{
        ClientId = $ClientId
        ClientSecret = $ClientSecretPlain
        RefreshToken = $cleanRefreshToken
    }

    # Save account.json with clean formatting (no extra newlines)
    $accountConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $accountPath -Encoding UTF8 -NoNewline
    Write-LocalizedHost -key 'AccountSaved' -color Green -args $accountPath

    # ============================================================
    # Step 5: Test Access Token with Microsoft Graph
    # ============================================================
    Write-Host "`n============================================================" -ForegroundColor Yellow
    Write-LocalizedHost -key 'Step5' -color Yellow
    Write-Host "============================================================`n" -ForegroundColor Yellow
    
    $headers = @{
        Authorization = "Bearer $($tokenResponse.access_token)"
    }
    
    try {
        Write-LocalizedHost -key 'TestingGraph' -color Cyan
        $meResponse = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/me' -Headers $headers
        Write-LocalizedHost -key 'UserInfoSuccess' -color Green
        Write-LocalizedHost -key 'DisplayName' -color Cyan -args $meResponse.displayName
        Write-LocalizedHost -key 'UserPrincipalName' -color Cyan -args $meResponse.userPrincipalName
        Write-LocalizedHost -key 'Mail' -color Cyan -args $meResponse.mail
    } catch {
        Write-LocalizedHost -key 'TestWarning' -color Yellow
        Write-Host $_.Exception.Message -ForegroundColor Yellow
    }
    
    # ============================================================
    # Generate Config.json Template
    # ============================================================
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-LocalizedHost -key 'ConfigFormat' -color Cyan
    Write-Host "============================================================`n" -ForegroundColor Cyan
    
    $configTemplate = @"
{
  "ClientId": "$ClientId",
  "ClientSecret": "$ClientSecretPlain",
  "RefreshToken": "$cleanRefreshToken"
}
"@
    
    Write-Host $configTemplate -ForegroundColor Yellow
    
    # Copy to clipboard if supported
    try {
        $configTemplate | Set-Clipboard
        Write-Host "`n" -NoNewline
        Write-LocalizedHost -key 'CopiedToClipboard' -color Green
    } catch {
        Write-Host "`n" -NoNewline
        Write-LocalizedHost -key 'ManualCopy' -color Yellow
    }
    
} catch {
    Write-Host "`n" -NoNewline
    Write-LocalizedHost -key 'TokenFailed' -color Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    
    # Display detailed error information if available
    if ($_.ErrorDetails.Message) {
        try {
            $errorDetail = $_.ErrorDetails.Message | ConvertFrom-Json
            Write-LocalizedHost -key 'ErrorCode' -color Red -args $errorDetail.error
            Write-Host "  $((Get-LocalizedText -key 'DescriptionLabel')) $($errorDetail.error_description)" -ForegroundColor Red
        } catch {
            Write-Host $_.ErrorDetails.Message -ForegroundColor Red
        }
    }
    exit 1
}

# ============================================================
# Script Completion
# ============================================================
Write-Host "`n============================================================" -ForegroundColor Green
Write-LocalizedHost -key 'ScriptComplete' -color Green
Write-Host "============================================================`n" -ForegroundColor Green
