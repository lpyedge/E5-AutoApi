https://entra.microsoft.com/#view/Microsoft_AAD_IAM/TenantOverview.ReactView?Microsoft_AAD_IAM_legacyAADRedirect=true
在 Entra 管理中心注册应用并配置重定向

App registrations > New registration，记录 client_id、tenant_id；Authentication > 添加 Web/SPA Redirect URI（如 https://localhost:53682/callback），启用授权码流场景所需设置。

证书和密码 > 客户端密码 > 新客户端密码 记录生成的 client_secret

添加 Delegated 权限（以及 offline_access）

API permissions > Add a permission > Microsoft Graph > Delegated permissions，添加所需 delegated 权限（如 Files.ReadWrite、Mail.ReadWrite 等）；授权码流要在 authorize 请求中包含 offline_access 才能返回 refresh token。

openid、profile、offline_access（为了拿 refresh token）
User.Read（基础）
Files.ReadWrite（OneDrive/Excel）
Tasks.ReadWrite（To Do）
Mail.ReadWrite、Mail.Send（邮件/草稿/文件夹/规则/发送）
Contacts.ReadWrite（联系人）
Calendars.ReadWrite（日历）
Notes.ReadWrite 或 Notes.ReadWrite.All（OneNote 页面）
People.Read、Presence.Read（people/presence）
Directory.ReadWrite.All
User.ReadWrite.All

添加完毕后 > 代表xxxx授予管理员同意

执行 request token.ps1 获取 refresh token

Settings - Actions - General - Workflow permissions
(check) Read and write permissions 