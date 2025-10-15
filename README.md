# Microsoft Graph API 自動化工具

一個基於 C\# .NET 的 Microsoft Graph API 自動化工具,支援 Office 365 服務的持續讀寫操作。採用 PKCE OAuth 授權流程和自動令牌刷新機制。

## 功能特色

### 支援的操作

#### 讀取模式

- **使用者資料**:顯示名稱、電子郵件、狀態、聯絡人、主管、直屬下級
- **OneDrive**:檔案、資料夾、配額、最近項目、共享項目
- **郵件**:訊息、資料夾、類別、草稿、已傳送項目
- **行事曆**:事件、行事曆檢視、權限、行事曆群組
- **聯絡人**:聯絡人清單和資料夾
- **待辦事項**:工作清單和工作
- **OneNote**:筆記本、節、頁面
- **SharePoint**:網站和磁碟機
- **Teams**:已加入的團隊(需要 Team.ReadBasic.All 權限)
- **目錄**:使用者、群組、授權(需要管理員權限)


#### 寫入模式(自動清理)

- **OneDrive**:上傳/刪除檔案、建立資料夾、複製/移動檔案、版本管理
- **Excel**:建立活頁簿、新增工作表、建立表格、寫入資料
- **郵件**:建立/刪除草稿、建立資料夾、管理規則、轉寄/回覆訊息
- **行事曆**:建立/刪除事件、接受/拒絕邀請
- **聯絡人**:建立/刪除聯絡人
- **待辦事項**:建立/刪除工作清單和工作、完成工作
- **OneNote**:建立/刪除頁面
- **使用者擴充**:建立/刪除開放擴充
- **群組**:讀取成員資格(建立群組需要管理員權限)


### 核心功能

- **PKCE OAuth 流程**:無需用戶端密碼的安全授權(適用於公開用戶端)
- **自動令牌刷新**:將更新後的刷新令牌保存至 Config.json 或 GitHub Secrets
- **可配置操作**:對執行的操作進行細緻控制
- **資源清理**:自動移除所有建立的測試資源
- **速率限制**:內建指數退避重試邏輯
- **CI/CD 就緒**:GitHub Actions 整合與環境變數支援


## 先決條件

1. **Azure AD 應用程式註冊**
    - Client ID(用戶端 ID)
    - Client Secret(用戶端密碼,機密用戶端需要)
    - Tenant ID(租戶 ID)
2. **委派權限**(見下方必要權限)
3. **.NET 10.0 SDK** 或更高版本
4. **PowerShell 5.1+**(用於令牌取得指令碼)

## 快速開始

### 步驟 1:註冊 Azure AD 應用程式

前往 [Azure Entra 管理中心](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/TenantOverview.ReactView)

#### 應用程式註冊

1. 導航至**應用程式註冊** > **新增註冊**
2. 記下**用戶端 ID** 和**租戶 ID**
3. 前往**驗證** > 新增平台 > **Web**
4. 新增重新導向 URI:`http://localhost` 或 `https://login.microsoftonline.com/common/oauth2/nativeclient`
5. 啟用**授權碼流程**

#### 用戶端密碼(機密用戶端)

1. 導航至**憑證與密碼** > **用戶端密碼**
2. 點擊**新增用戶端密碼**
3. 記下生成的密碼值

#### API 權限

1. 導航至 **API 權限** > **新增權限**
2. 選擇 **Microsoft Graph** > **委派的權限**
3. 新增以下必要權限
4. 點擊**為 [租戶] 授予管理員同意**

### 步驟 2:必要權限

```
openid
profile
offline_access
User.Read
User.ReadWrite.All
Sites.Read.All
Files.ReadWrite
Tasks.ReadWrite
Mail.ReadWrite
Mail.Send
Contacts.ReadWrite
Calendars.ReadWrite
Notes.ReadWrite (或 Notes.ReadWrite.All)
People.Read
Presence.Read
Directory.ReadWrite.All
Group.ReadWrite.All
```


### 步驟 3:取得刷新令牌

#### 使用 PowerShell 指令碼

**Windows (CMD)**:

```cmd
powershell -ExecutionPolicy Bypass -File .\request_token.ps1
```

**PowerShell**:

```powershell
.\request_token.ps1
```
##### PowerShell 指令碼執行被封鎖

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\request_token.ps1
```

**指令碼功能**:

1. 開啟瀏覽器進行 OAuth 授權
2. 提示貼上登入後的回呼 URL
3. 使用 PKCE 交換授權碼為令牌
4. 將令牌儲存至 `tokens_<timestamp>.json`
5. 將帳戶配置儲存至 `account_<timestamp>.json`
6. 呼叫 Microsoft Graph `/me` 端點測試令牌

**生成的檔案**:

- `tokens_<timestamp>.json`:完整的令牌回應(access_token、refresh_token、expires_in)
- `account_<timestamp>.json`:應用程式配置(ClientId、ClientSecret、RefreshToken)


### 步驟 4:配置應用程式

在專案根目錄建立 `Config.json`:

```json
{
  "Accounts": [
    {
      "ClientId": "your-client-id",
      "ClientSecret": "your-client-secret",
      "RefreshToken": "0.AX...your-refresh-token..."
    }
  ],
  "Prefixes": ["TEST", "AUTO"],
  "Run": {
    "Rounds": 3,
    "ApiDelay": {
      "Enabled": true,
      "MinSeconds": 2,
      "MaxSeconds": 5
    },
    "RoundsDelay": {
      "Enabled": true,
      "MinSeconds": 10,
      "MaxSeconds": 30
    },
    "AccountDelay": {
      "Enabled": true,
      "MinSeconds": 60,
      "MaxSeconds": 120
    }
  },
  "Features": {
    "Read": {
      "TaskMin": 8,
      "UseExtendedApis": true
    },
    "Write": {
      "TaskMin": 6,
      "UploadRandomFile": true,
      "Excel": true,
      "Todo": true,
      "CalendarEvent": true,
      "Contacts": true,
      "MailDraft": true,
      "MailFolder": true,
      "MailRule": true,
      "OneNotePage": true,
      "DriveFolderWithShareLink": true,
      "UserOpenExtension": true,
      "GroupJoin": false,
      "MailForwardReply": false,
      "FileCopyMove": false,
      "CalendarEventResponse": false,
      "TaskCompletion": false
    }
  }
}
```


### 步驟 5:執行應用程式

**僅讀取模式**:

```bash
dotnet run Program.cs read
```

**僅寫入模式**:

```bash
dotnet run Program.cs write
```

**兩種模式**(預設):

```bash
dotnet run Program.cs
# 或
dotnet run Program.cs both
```

**僅刷新令牌**:

```bash
dotnet run Program.cs refresh
```



## GitHub Actions 整合

### 設定工作流程權限

1. 導航至儲存庫**設定** > **Actions** > **一般**
2. 在**工作流程權限**下,勾選**讀取和寫入權限**
3. 儲存變更

### 建立 PAT (Personal access token)

1. 前往 Settings → Developer settings → Personal access tokens → Fine‑grained tokens → Generate new token，填寫名稱後建立令牌。​
2. 在 Repository access 選擇 Only select repositories，稍後挑選需要操作的目標儲存庫以避免過度授權。
3. 對目標儲存庫授予 Repository permissions 的 Secrets: Read and Write 權限。​
4. 點選Generate token按鈕並儲存產生的token,只會顯示一次,務必提前儲存到本地.稍微需要設定到儲存庫的Secrets中.

### 配置 Secrets

新增以下儲存庫 Secrets:


| Secret | 說明 |
| :-- | :-- |
| ACCOUNTS_JSON | 帳戶配置的 JSON 陣列 |
| PAT | 之前建立的Personal access token |

**ACCOUNTS_JSON 範例**:

```json
[{"ClientId":"...","ClientSecret":"...","RefreshToken":"..."}]
```


### 工作流程檔案

專案包含三個 GitHub Actions 工作流程:

#### read.yml

- **功能**:執行僅讀取操作,不建立、修改或刪除任何資源


#### write.yml

- **功能**:執行寫入操作,並自動清理所有建立的資源


#### refresh.yml

- **功能**:刷新 OAuth2 令牌,並將更新後的令牌加密寫回 GitHub Secrets


## 專案結構

```
E5-AUTOAPI/
├── .github/
│   └── workflows/
│       ├── read.yml        # 讀取操作工作流程
│       ├── write.yml       # 寫入操作工作流程
│       └── refresh.yml     # 令牌刷新工作流程
├── src/
│   ├── Config.json         # 應用程式配置檔案
│   └── Program.cs          # 主程式邏輯
├── request_token.ps1       # OAuth 令牌取得指令碼
├── README.md               # 專案說明文件
└── LICENSE                 # 授權條款
```


## 設定參考

### Accounts(帳戶)

包含 OAuth 憑證的 Microsoft 365 帳戶陣列。


| 欄位 | 類型 | 必要 | 說明 |
| :-- | :-- | :-- | :-- |
| ClientId | string | 是 | Azure AD 的應用程式(用戶端)ID |
| ClientSecret | string | 是* | 用戶端密碼值(*機密用戶端需要) |
| RefreshToken | string | 是 | 透過授權流程取得的 OAuth 刷新令牌 |

### Run(執行配置)

控制執行流程和操作之間的時間間隔。


| 屬性 | 說明 |
| :-- | :-- |
| Rounds | 每個帳戶的執行輪數 |
| ApiDelay | 個別 API 呼叫之間的延遲 |
| RoundsDelay | 執行輪次之間的延遲 |
| AccountDelay | 不同帳戶之間的延遲 |

### Features(功能配置)

#### 讀取功能

| 屬性 | 類型 | 預設值 | 說明 |
| :-- | :-- | :-- | :-- |
| TaskMin | int | 8 | 要執行的最小讀取端點數量 |
| UseExtendedApis | bool | true | 啟用擴充 API 呼叫(需要額外權限) |

#### 寫入功能

切換個別寫入操作:


| 屬性 | 說明 |
| :-- | :-- |
| UploadRandomFile | 上傳和刪除測試檔案 |
| Excel | Excel 活頁簿操作 |
| Todo | 待辦事項清單操作 |
| CalendarEvent | 行事曆事件 CRUD |
| Contacts | 聯絡人 CRUD |
| MailDraft | 郵件草稿操作 |
| MailFolder | 郵件資料夾管理 |
| MailRule | 收件匣規則管理 |
| OneNotePage | OneNote 頁面操作 |
| DriveFolderWithShareLink | OneDrive 共用 |
| UserOpenExtension | 使用者擴充操作 |

## 常見問題排解

### 常見錯誤

#### 錯誤:無法取得令牌

- 驗證 Client ID、Client Secret 和 Refresh Token 是否正確
- 檢查刷新令牌是否已過期(重新執行 `request_token.ps1`)
- 確保重新導向 URI 與 Azure AD 配置相符


#### 錯誤:權限不足

- 在 Azure AD 中授予必要權限的管理員同意
- 驗證已新增委派權限(而非應用程式權限)


#### 429 請求過多

- 工具會自動以指數退避重試
- 增加配置中的 `ApiDelay` 以降低請求速率


#### 令牌刷新失敗 AADSTS700222

- 刷新令牌已過期
- 使用 `request_token.ps1` 重新授權以取得新的刷新令牌


## 安全性考量

### 最佳實踐

1. **絕不提交敏感資料**:將 `Config.json`、`tokens_*.json`、`account_*.json` 加入 `.gitignore`
2. **刷新令牌輪換**:刷新令牌會自動更新並持久化,使用後舊令牌會失效
3. **最小權限原則**:僅授予必要的委派權限,測試與生產環境使用不同帳戶
4. **PKCE 流程**:公開用戶端使用 PKCE(無需用戶端密碼),比傳統授權碼流程更安全
5. **用戶端密碼保護**:將用戶端密碼儲存在安全保管庫(Azure Key Vault、GitHub Secrets),定期輪換密碼

## 依賴項

- **.NET 10.0+**:執行階段和 SDK
- **Sodium.Core**:用於 GitHub Secrets 的 Libsodium 加密(NuGet 套件)
- **System.Text.Json**:原生 JSON 序列化與來源產生器

***

**免責聲明**:本工具專為測試和自動化目的設計,使用前請確保符合您組織的政策和 Microsoft 的服務條款。
