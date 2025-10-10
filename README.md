# Microsoft Graph API Automation Tool

A C# .NET automation tool for Microsoft Graph API that performs continuous read/write operations across Office 365 services. Supports delegated permissions with PKCE OAuth flow and automatic token refresh.

## Features

### Supported Operations

#### Read Mode
- **User Profile**: Display name, email, presence, people, manager, direct reports
- **OneDrive**: Files, folders, quota, recent items, shared items
- **Mail**: Messages, folders, categories, drafts, sent items
- **Calendar**: Events, calendar view, permissions, calendar groups
- **Contacts**: Contacts list and folders
- **To Do**: Task lists and tasks
- **OneNote**: Notebooks, sections, pages
- **SharePoint**: Sites and drives
- **Teams**: Joined teams (requires Team.ReadBasic.All)
- **Directory**: Users, groups, licenses (requires admin permissions)

#### Write Mode (with automatic cleanup)
- **OneDrive**: Upload/delete files, create folders, copy/move files, manage versions
- **Excel**: Create workbooks, add worksheets, create tables, write data
- **Mail**: Create/delete drafts, create folders, manage rules, forward/reply messages
- **Calendar**: Create/delete events, accept/decline invitations
- **Contacts**: Create/delete contacts
- **To Do**: Create/delete task lists and tasks, complete tasks
- **OneNote**: Create/delete pages
- **User Extensions**: Create/delete open extensions
- **Groups**: Read membership (group creation requires admin)

### Key Features

- **PKCE OAuth Flow**: Secure authorization without client secret for public clients
- **Automatic Token Refresh**: Persists updated refresh tokens to Config.json or GitHub Secrets
- **Configurable Operations**: Fine-grained control over which operations to execute
- **Resource Cleanup**: Automatically removes all created test resources
- **Rate Limiting**: Built-in retry logic with exponential backoff
- **Multi-Language Support**: English, Traditional Chinese, Japanese (PowerShell script)
- **CI/CD Ready**: GitHub Actions integration with environment variable support

## Prerequisites

1. **Azure AD App Registration**
   - Client ID
   - Client Secret (for confidential clients)
   - Tenant ID
2. **Delegated Permissions** (see [Required Permissions](#required-permissions))
3. **.NET 8.0 SDK** or higher
4. **PowerShell 5.1+** (for token acquisition script)

## Quick Start

### 1. Register Azure AD Application

Visit [Azure Entra Admin Center](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/TenantOverview.ReactView)

#### App Registration
1. Navigate to **App registrations** > **New registration**
2. Note down **Client ID** and **Tenant ID**
3. Go to **Authentication** > Add platform > **Web**
4. Add Redirect URI: `http://localhost` or `https://login.microsoftonline.com/common/oauth2/nativeclient`
5. Enable **Authorization code flow**

#### Client Secret (for confidential clients)
1. Navigate to **Certificates & secrets** > **Client secrets**
2. Click **New client secret**
3. Note down the generated secret value

#### API Permissions
1. Navigate to **API permissions** > **Add a permission**
2. Select **Microsoft Graph** > **Delegated permissions**
3. Add the required permissions (see below)
4. Click **Grant admin consent for [Tenant]**

### 2. Required Permissions

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
Notes.ReadWrite (or Notes.ReadWrite.All)
People.Read
Presence.Read
Directory.ReadWrite.All
Group.ReadWrite.All
```

### 3. Obtain Refresh Token

#### Using PowerShell Script

**Windows (CMD)**:
```cmd
powershell -ExecutionPolicy Bypass -File .\request_token.ps1
```

**PowerShell**:
```powershell
.\request_token.ps1
```

**What the script does**:
1. Opens browser for OAuth authorization
2. Prompts to paste the callback URL after login
3. Exchanges authorization code for tokens using PKCE
4. Saves tokens to `tokens_<timestamp>.json`
5. Saves account configuration to `account_<timestamp>.json`
6. Tests token by calling Microsoft Graph `/me` endpoint

**Generated Files**:
- `tokens_<timestamp>.json`: Complete token response (access_token, refresh_token, expires_in)
- `account_<timestamp>.json`: Application configuration (ClientId, ClientSecret, RefreshToken)

### 4. Configure Application

Create `Config.json` in the project root:

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
  },
  "Assets": {
    "Excel": {
      "MinimalWorkbookBase64": "<base64-encoded-xlsx-file>"
    }
  }
}
```

### 5. Run Application

**Read Mode Only**:
```bash
dotnet run -- read
```

**Write Mode Only**:
```bash
dotnet run -- write
```

**Both Modes** (default):
```bash
dotnet run
# or
dotnet run -- both
```

**Refresh Tokens Only**:
```bash
dotnet run -- refresh
```

## Configuration Reference

### Accounts
Array of Microsoft 365 accounts with OAuth credentials.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| ClientId | string | Yes | Application (client) ID from Azure AD |
| ClientSecret | string | Yes* | Client secret value (*required for confidential clients) |
| RefreshToken | string | Yes | OAuth refresh token obtained via authorization flow |

### Prefixes
Array of strings used for naming created resources. Enables cleanup by prefix matching.

**Example**:
```json
"Prefixes": ["TEST", "AUTO", "DEMO"]
```

### Run Configuration

Controls execution flow and timing between operations.

| Property | Description |
|----------|-------------|
| Rounds | Number of execution rounds per account |
| ApiDelay | Delay between individual API calls |
| RoundsDelay | Delay between execution rounds |
| AccountDelay | Delay between different accounts |

Each delay configuration supports:
```json
{
  "Enabled": true,
  "MinSeconds": 2,
  "MaxSeconds": 5
}
```

### Features Configuration

#### Read Features
| Property | Type | Default | Description |
|----------|------|---------|-------------|
| TaskMin | int | 8 | Minimum number of read endpoints to execute |
| UseExtendedApis | bool | true | Enable extended API calls (requires additional permissions) |

#### Write Features
Toggle individual write operations:

| Property | Description |
|----------|-------------|
| UploadRandomFile | Upload and delete test files |
| Excel | Excel workbook operations |
| Todo | To Do list operations |
| CalendarEvent | Calendar event CRUD |
| Contacts | Contact CRUD |
| MailDraft | Mail draft operations |
| MailFolder | Mail folder management |
| MailRule | Inbox rule management |
| OneNotePage | OneNote page operations |
| DriveFolderWithShareLink | OneDrive sharing |
| UserOpenExtension | User extension operations |
| GroupJoin | Group membership (read-only) |
| MailForwardReply | Email forwarding/replying |
| FileCopyMove | File copy/move operations |
| CalendarEventResponse | Accept/decline events |
| TaskCompletion | Mark tasks as complete |

## GitHub Actions Integration

### Setup Workflow Permissions

1. Navigate to repository **Settings** > **Actions** > **General**
2. Under **Workflow permissions**, check **Read and write permissions**
3. Save changes

### Configure Secrets

Add the following repository secrets:

| Secret | Description |
|--------|-------------|
| ACCOUNTS_JSON | JSON array of account configurations |
| GH_TOKEN | GitHub Personal Access Token with `repo` scope |
| GH_REPO | Repository in format `owner/repo` |

**ACCOUNTS_JSON Example**:
```json
[{"ClientId":"...","ClientSecret":"...","RefreshToken":"..."}]
```

### Multiple Accounts

The tool supports multiple accounts in `Config.json`:

```json
{
  "Accounts": [
    {
      "ClientId": "account-1-client-id",
      "ClientSecret": "account-1-secret",
      "RefreshToken": "account-1-refresh-token"
    },
    {
      "ClientId": "account-2-client-id",
      "ClientSecret": "account-2-secret",
      "RefreshToken": "account-2-refresh-token"
    }
  ]
}
```

### Environment Variable Override

For CI/CD scenarios, set `ACCOUNTS_JSON` environment variable:

```bash
export ACCOUNTS_JSON='[{"ClientId":"...","ClientSecret":"...","RefreshToken":"..."}]'
dotnet run
```

This overrides accounts from `Config.json`.

### Token Refresh Behavior

When running in **refresh mode**:
- Tokens are refreshed for all configured accounts
- Updated refresh tokens are persisted back to `Config.json` (local) or GitHub Secrets (CI/CD)
- Fatal errors (expired refresh token, invalid client secret) exit with code 1

### Cleanup Strategy

The tool uses prefix-based cleanup:
1. All created resources are named with configured prefixes (e.g., `TEST_File_12345.txt`)
2. After each round, cleanup methods search and delete resources matching prefixes
3. Supports cleanup across all services (OneDrive, Mail, Calendar, Contacts, etc.)

## Troubleshooting

### Common Issues

#### Error: Failed to obtain token
- Verify Client ID, Client Secret, and Refresh Token are correct
- Check if refresh token has expired (re-run `request_token.ps1`)
- Ensure redirect URI matches Azure AD configuration

#### Error: Insufficient privileges
- Grant admin consent for required permissions in Azure AD
- Verify delegated permissions are added (not application permissions)

#### 429 Too Many Requests
- Tool automatically retries with exponential backoff
- Increase `ApiDelay` in configuration to reduce request rate

#### Token refresh failed with AADSTS700222
- Refresh token has expired
- Re-authorize using `request_token.ps1` to obtain new refresh token

#### PowerShell script execution blocked
**Windows (CMD)**:
```cmd
powershell -ExecutionPolicy Bypass -File .\request_token.ps1
```

**PowerShell** (temporary):
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\request_token.ps1
```


## Security Considerations

### Best Practices

1. **Never commit sensitive data**:
   - Add `Config.json`, `tokens_*.json`, `account_*.json` to `.gitignore`
   - Use GitHub Secrets for CI/CD workflows

2. **Refresh Token Rotation**:
   - Refresh tokens are automatically updated and persisted
   - Old refresh tokens are invalidated after use

3. **Least Privilege Principle**:
   - Only grant required delegated permissions
   - Use separate accounts for testing vs. production

4. **PKCE Flow**:
   - Use PKCE for public clients (no client secret required)
   - More secure than traditional authorization code flow

5. **Client Secret Protection**:
   - Store client secrets in secure vaults (Azure Key Vault, GitHub Secrets)
   - Rotate secrets regularly

## Dependencies

- **.NET 10.0+**: Runtime and SDK
- **Sodium.Core**: Libsodium encryption for GitHub Secrets (NuGet package)
- **System.Text.Json**: Native JSON serialization with source generators

## Project Structure

```
.
└── src/
├   └── workflows/
├      └── Program.cs       # Main application logic
├      └── Config.json      # Application configuration
├── request_token.ps1       # OAuth token acquisition script
├── README.md               # This file
└── .github/
    └── workflows/
        └── read.yml        # GitHub Actions workflow
        └── write.yml       # GitHub Actions workflow
        └── refresh.yml     # GitHub Actions workflow
```

## Performance Considerations

- **Rate Limiting**: Microsoft Graph enforces rate limits per tenant and user
- **Retry Logic**: Automatic exponential backoff for 429/503 errors
- **Batch Operations**: Consider implementing batch requests for bulk operations
- **Concurrent Execution**: Avoid running multiple instances simultaneously for the same account

## License

This project is provided as-is for educational and testing purposes. Use at your own risk.

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Support

For issues and questions:
- Open an issue on GitHub
- Check [Microsoft Graph API documentation](https://learn.microsoft.com/graph/)
- Review [Azure AD authentication docs](https://learn.microsoft.com/azure/active-directory/)

## Acknowledgments

- Microsoft Graph API team for comprehensive documentation
- .NET community for excellent tooling and libraries
- Contributors and users who provide feedback and improvements

---

**Disclaimer**: This tool is designed for testing and automation purposes. Ensure compliance with your organization's policies and Microsoft's terms of service before use.
