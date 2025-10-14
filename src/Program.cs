#:package Sodium.Core@1.4.0

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using System.Threading.Tasks;
using System.Runtime.CompilerServices;

// ============================================================
// Microsoft Graph API Automation Tool
// Supports Read/Write/Refresh modes for Office 365 operations
// ============================================================

public class Program
{
    // ============== Static Fields & Configuration ==============

    private static readonly HttpClient _http = new HttpClient();
    private static readonly Random _rng = new Random();
    private static Config? _cfg;
    private const string ConfigPath = "Config.json";
    private static bool _loadedFromEnvironment = false;
    private static readonly JsonSerializerOptions JsonWriteOptions = CreateWriteOptions();

    // ============== Initialization & Configuration ==============

    /// <summary>
    /// Creates JSON serialization options with source generator support and reflection fallback.
    /// </summary>
    private static JsonSerializerOptions CreateWriteOptions()
    {
        var opt = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        // Add source generator context for performance
        opt.TypeInfoResolverChain.Add(ConfigContext.Default);
        // Fallback to reflection for anonymous types and Dictionary
        opt.TypeInfoResolverChain.Add(new DefaultJsonTypeInfoResolver());
        return opt;
    }

    /// <summary>
    /// Helper to create JSON content for HTTP requests.
    /// </summary>
    private static StringContent JsonContent(object payload) =>
        new StringContent(JsonSerializer.Serialize(payload, JsonWriteOptions), Encoding.UTF8, "application/json");

    // ============== Entry Point ==============

    public static async Task Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        // Load configuration from Config.json
        _cfg = await LoadConfigAsync();
        if (_cfg == null)
        {
            Console.WriteLine($" [ERROR] Failed to load configuration. Please check {ConfigPath}.");
            return;
        }

        // Override accounts from environment variable if available
        OverrideAccountsFromEnvironment(_cfg);

        // Parse execution mode from command line arguments
        string mode = (args.Length > 0 ? args[0] : "both").Trim().ToLowerInvariant();
        bool refreshToken = mode is "refresh";
        bool runRead = mode is "read" or "both";
        bool runWrite = mode is "write" or "both";

        // Execute refresh mode (update tokens only)
        if (refreshToken)
        {
            await RefreshTokensAsync(_cfg, _loadedFromEnvironment);
        }
        else
        {
            // Execute read/write modes for all accounts
            for (int i = 0; i < _cfg.Accounts.Count; i++)
            {
                var acct = _cfg.Accounts[i];
                Console.WriteLine($"========== Account #{i + 1} ==========");

                // Obtain access token
                var token = await GetAccessTokenAsync(acct);
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.WriteLine(" [ERROR] Failed to obtain access_token, skipping this account.");
                    await DelayAsync(_cfg.Run?.AccountDelay);
                    continue;
                }

                // Execute configured rounds
                int rounds = Math.Max(1, _cfg.Run?.Rounds ?? 1);
                for (int r = 1; r <= rounds; r++)
                {
                    Console.WriteLine($"-- Round {r}/{rounds} --");

                    // Execute read operations
                    if (runRead) 
                        await RunReadModeAsync(token);

                    // Execute write operations
                    if (runWrite)
                    {
                        // Send notification email if configured
                        if (!string.IsNullOrWhiteSpace(_cfg.Notification?.Email?.ToAddress))
                        {
                            _ = SendEmailAsync(token, _cfg.Notification.Email.ToAddress!,
                                "Graph Automation Task Started",
                                $"Account {acct.ClientId} write task started at {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}");
                        }

                        // Pick random prefix for this round
                        string chosenPrefix = PickRandomPrefix(_cfg.Prefixes);
                        Console.WriteLine($" [INFO] Using prefix for this round: {chosenPrefix}");

                        await RunWriteModeAsync(token, chosenPrefix);
                        await CleanupAllPrefixesAsync(token, _cfg.Prefixes);
                    }

                    // Delay between rounds
                    if (r < rounds) 
                        await DelayAsync(_cfg.Run?.RoundsDelay);
                }

                // Delay between accounts
                if (i < _cfg.Accounts.Count - 1) 
                    await DelayAsync(_cfg.Run?.AccountDelay);
            }
        }

        Console.WriteLine("All done.");
    }

    // ============== Configuration Management ==============

    /// <summary>
    /// Gets the absolute path of a file relative to the source code location.
    /// </summary>
    static string GetSourceFilePath(string fileName, [CallerFilePath] string sourceFile = "")
    {
        return Path.Combine(
            Path.GetDirectoryName(sourceFile) ?? "",
            fileName
        );
    }

    /// <summary>
    /// Loads configuration from Config.json file.
    /// </summary>
    private static async Task<Config?> LoadConfigAsync()
    {
        var configPath = GetSourceFilePath(ConfigPath);
        if (!File.Exists(configPath))
        {
            Console.WriteLine($" [ERROR] Configuration file not found: {configPath}");
            return null;
        }

        try
        {
            var json = await File.ReadAllTextAsync(configPath, Encoding.UTF8);
            var cfg = JsonSerializer.Deserialize<Config>(json, ConfigContext.Default.Options);
            return cfg;
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [ERROR] Failed to parse configuration: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Overrides accounts from ACCOUNTS_JSON environment variable if present.
    /// Used for CI/CD scenarios where secrets are stored in environment variables.
    /// </summary>
    private static void OverrideAccountsFromEnvironment(Config cfg)
    {
        try
        {
            var json = Environment.GetEnvironmentVariable("ACCOUNTS_JSON");
            if (string.IsNullOrWhiteSpace(json))
                return; // No environment variable, keep original config

            var list = JsonSerializer.Deserialize<List<Config.AccountConfig>>(json, ConfigContext.Default.Options);
            if (list != null && list.Count > 0 &&
                list.All(a => !string.IsNullOrWhiteSpace(a.ClientId)
                           && !string.IsNullOrWhiteSpace(a.ClientSecret)
                           && !string.IsNullOrWhiteSpace(a.RefreshToken)))
            {
                cfg.Accounts = list; // Override accounts from config file
                _loadedFromEnvironment = true;
                Console.WriteLine($" [INFO] Loaded {list.Count} account(s) from ACCOUNTS_JSON environment variable.");
            }
            else
            {
                Console.WriteLine(" [WARN] ACCOUNTS_JSON is empty or incomplete, ignoring override.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [WARN] Failed to parse ACCOUNTS_JSON: {ex.Message}, ignoring override.");
        }
    }

    // ============== GitHub Secrets Management ==============

    /// <summary>
    /// Updates a GitHub repository secret using libsodium sealed box encryption.
    /// Used in refresh mode to persist updated refresh tokens.
    /// </summary>
    private static async Task<bool> UpsertGitHubSecretAsync(string name, string plaintext)
    {
        var owner_repo = Environment.GetEnvironmentVariable("REPO");
        var pat = Environment.GetEnvironmentVariable("PAT");

        if (string.IsNullOrWhiteSpace(owner_repo) || string.IsNullOrWhiteSpace(pat))
        {
            Console.WriteLine(" [ERROR] Missing REPO or PAT. Cannot update secret. Please set both environment variables.");
            return false;
        }

        // Factory function to generate HttpRequestMessage with common headers
        Func<HttpRequestMessage> reqGenerate = () =>
        {
            var req = new HttpRequestMessage();
            req.Headers.UserAgent.ParseAdd("dotnet-secrets-client");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", pat);
            req.Headers.Accept.ParseAdd("application/vnd.github+json");
            req.Headers.Add("X-GitHub-Api-Version", "2022-11-28");
            return req;
        };

        // Step 1: Get repository public key
        using var req0 = reqGenerate();
        req0.Method = HttpMethod.Get;
        req0.RequestUri = new Uri($"https://api.github.com/repos/{owner_repo}/actions/secrets/public-key");
        HttpResponseMessage pkJsonResponse;
        string pkJson;
        try
        {
            pkJsonResponse = await _http.SendAsync(req0);
            pkJson = await pkJsonResponse.Content.ReadAsStringAsync();
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [ERROR] Network error when calling secrets public-key endpoint: {ex.Message}");
            return false;
        }

        if (!pkJsonResponse.IsSuccessStatusCode)
        {
            var hint = ExtractErrorHint(pkJson);
            switch ((int)pkJsonResponse.StatusCode)
            {
                case 401:
                    Console.WriteLine($" [ERROR] 401 Unauthorized. Token invalid or expired. {hint} Please verify your PAT scopes (classic: repo; fine-grained: Secrets Read) and repo selection.");
                    break;
                case 403:
                    Console.WriteLine($" [ERROR] 403 Forbidden. Resource not accessible by integration. {hint} Likely using PAT lacks Secrets permission or repo access.");
                    break;
                case 404:
                    Console.WriteLine($" [ERROR] 404 Not Found. Check REPO value '{owner_repo}' and ensure the token has access to this repository (private repos require 'repo' scope). {hint}");
                    break;
                case 429:
                    Console.WriteLine($" [ERROR] 429 Rate limited by GitHub API. Please retry later. {hint}");
                    break;
                default:
                    Console.WriteLine($" [ERROR] Get public-key failed: {(int)pkJsonResponse.StatusCode}. {hint}");
                    break;
            }
            return false;
        }

        var pk = JsonSerializer.Deserialize(pkJson, ConfigContext.Default.PublicKeyResp);
        if (pk is null || string.IsNullOrWhiteSpace(pk.key) || string.IsNullOrWhiteSpace(pk.key_id))
        {
            Console.WriteLine($" [ERROR] Public-key payload missing required fields (key/key_id). Raw: {pkJson}");
            return false;
        }

        // ---- Step 2: Encrypt plaintext using libsodium sealed box (base64 encoded)
        byte[] pubKeyBytes;
        try
        {
            pubKeyBytes = Convert.FromBase64String(pk.key);
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [ERROR] Invalid base64 in GitHub public key: {ex.Message}");
            return false;
        }

        string encB64;
        try
        {
            var cipher = Sodium.SealedPublicKeyBox.Create(Encoding.UTF8.GetBytes(plaintext), pubKeyBytes);
            encB64 = Convert.ToBase64String(cipher);
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [ERROR] Encryption failed using libsodium: {ex.Message}");
            return false;
        }

        // ---- Step 3: PUT update secret
        using var req1 = reqGenerate();
        req1.Method = HttpMethod.Put;
        req1.RequestUri = new Uri($"https://api.github.com/repos/{owner_repo}/actions/secrets/{name}");
        req1.Content = JsonContent(new UpsertReq(encB64, pk.key_id));

        HttpResponseMessage resp;
        string body;
        try
        {
            resp = await _http.SendAsync(req1);
            body = await resp.Content.ReadAsStringAsync();
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [ERROR] Network error when updating secret: {ex.Message}");
            return false;
        }

        if (!resp.IsSuccessStatusCode)
        {
            var hint = ExtractErrorHint(body);
            switch ((int)resp.StatusCode)
            {
                case 401:
                    Console.WriteLine($" [ERROR] 401 Unauthorized when updating secret. Token invalid/expired or missing required scopes. {hint}");
                    break;
                case 403:
                    Console.WriteLine($" [ERROR] 403 Forbidden when updating secret. Token lacks 'Secrets: write' (fine-grained) or 'repo' (classic), or repo not selected. {hint}");
                    break;
                case 404:
                    Console.WriteLine($" [ERROR] 404 Not Found when updating secret. Verify REPO and repository access. {hint}");
                    break;
                case 422:
                    Console.WriteLine($" [ERROR] 422 Validation failed when updating secret. Ensure key_id matches the latest public key and payload format is correct. {hint}");
                    break;
                case 429:
                    Console.WriteLine($" [ERROR] 429 Rate limited when updating secret. Please retry later. {hint}");
                    break;
                default:
                    Console.WriteLine($" [ERROR] Update secret failed: {(int)resp.StatusCode}. {hint}");
                    break;
            }
            return false;
        }

        Console.WriteLine($" [OK] Secret '{name}' updated successfully for {owner_repo} (HTTP {(int)resp.StatusCode}).");
        return true;
    }
    
    /// <summary>
    /// best-effort to surface GitHub error message
    /// </summary>
    /// <param name="json"></param>
    /// <returns></returns>
    static string ExtractErrorHint(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var msg = root.TryGetProperty("message", out var m) ? m.GetString() : null;
            var url = root.TryGetProperty("documentation_url", out var u) ? u.GetString() : null;
            if (!string.IsNullOrWhiteSpace(msg) || !string.IsNullOrWhiteSpace(url))
                return $"Message: {msg ?? "-"} | Doc: {url ?? "-"}";
        }
        catch { /* ignore */ }
        return $"Body: {json}";
    }

    // ============== Microsoft Graph API Endpoints ==============

    private static class EP
    {
        // OAuth endpoints
        public const string TokenUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
        public const string RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient";
        public const string V1 = "https://graph.microsoft.com/v1.0";
        public const string Beta = "https://graph.microsoft.com/beta";

        // OneDrive endpoints
        public static string SearchDriveItems(string q) => $"{V1}/me/drive/root/search(q='{Uri.EscapeDataString(q)}')";
        public static string DeleteDriveItem(string id) => $"{V1}/me/drive/items/{id}";
        public static string UploadRootContent(string fileName) => $"{V1}/me/drive/root:/{Uri.EscapeDataString(fileName)}:/content";
        public static string CreateFolderUnderRoot => $"{V1}/me/drive/root/children";
        public static string DriveItemChildren(string id) => $"{V1}/me/drive/items/{id}/children";
        public static string DriveItemCreateLink(string id) => $"{V1}/me/drive/items/{id}/createLink";
        public static string DriveItemPermissions(string id, string permId) => $"{V1}/me/drive/items/{id}/permissions/{permId}";
        public static string UploadUnderItem(string parentId, string name) => $"{V1}/me/drive/items/{parentId}:/{Uri.EscapeDataString(name)}:/content";
        public static string CopyDriveItem(string itemId) => $"{V1}/me/drive/items/{itemId}/copy";
        public static string UpdateDriveItem(string itemId) => $"{V1}/me/drive/items/{itemId}";
        public static string DriveItemVersions(string itemId) => $"{V1}/me/drive/items/{itemId}/versions";
        public static string RestoreDriveItemVersion(string itemId, string versionId) => $"{V1}/me/drive/items/{itemId}/versions/{versionId}/restoreVersion";


        // Excel endpoints
        public static string ExcelWorksheets(string itemId) => $"{V1}/me/drive/items/{itemId}/workbook/worksheets";
        public static string ExcelTablesAdd(string itemId, string sheetName) => $"{V1}/me/drive/items/{itemId}/workbook/worksheets/{Uri.EscapeDataString(sheetName)}/tables/add";
        public static string ExcelTableRowsAdd(string itemId, string tableId) => $"{V1}/me/drive/items/{itemId}/workbook/tables/{Uri.EscapeDataString(tableId)}/rows/add";

        // To Do endpoints
        public static string TodoLists => $"{V1}/me/todo/lists";
        public static string TodoListById(string listId) => $"{V1}/me/todo/lists/{Uri.EscapeDataString(listId)}";
        public static string TodoTasks(string listId) => $"{V1}/me/todo/lists/{Uri.EscapeDataString(listId)}/tasks";
        public static string TaskChecklistItems(string listId, string taskId) => $"{V1}/me/todo/lists/{listId}/tasks/{taskId}/checklistItems";
        public static string CompleteTask(string listId, string taskId) => $"{V1}/me/todo/lists/{listId}/tasks/{taskId}";

        // Outlook mail endpoints
        public static string SendMail => $"{V1}/me/sendMail";
        public static string CreateMessage => $"{V1}/me/messages";
        public static string MoveMessage(string messageId) => $"{V1}/me/messages/{messageId}/move";
        public static string MessageById(string id) => $"{V1}/me/messages/{id}";
        public static string MailFolders => $"{V1}/me/mailFolders";
        public static string MailFolderById(string id) => $"{V1}/me/mailFolders/{id}";
        public static string InboxRules => $"{V1}/me/mailFolders/Inbox/messageRules";
        public static string InboxRuleById(string id) => $"{V1}/me/mailFolders/Inbox/messageRules/{id}";   
        public static string ForwardMessage(string messageId) => $"{V1}/me/messages/{messageId}/forward";
        public static string ReplyMessage(string messageId) => $"{V1}/me/messages/{messageId}/reply";
        public static string ReplyAllMessage(string messageId) => $"{V1}/me/messages/{messageId}/replyAll";


        // Contacts endpoints
        public static string Contacts => $"{V1}/me/contacts";
        public static string ContactById(string id) => $"{V1}/me/contacts/{id}";

        // Calendar endpoints
        public static string Events => $"{V1}/me/events";
        public static string EventById(string id) => $"{V1}/me/events/{id}";
        public static string CalendarEvents(string calendarId) => $"{V1}/me/calendars/{calendarId}/events";
        public static string AcceptEvent(string eventId) => $"{V1}/me/events/{eventId}/accept";
        public static string DeclineEvent(string eventId) => $"{V1}/me/events/{eventId}/decline";
        public static string TentativelyAcceptEvent(string eventId) => $"{V1}/me/events/{eventId}/tentativelyAccept";
        public static string ForwardEvent(string eventId) => $"{V1}/me/events/{eventId}/forward";


        // OneNote endpoints
        public static string OneNotePages => $"{V1}/me/onenote/pages";
        public static string OneNotePageById(string id) => $"{V1}/me/onenote/pages/{id}";

        // User open extensions endpoints
        public static string UserExtensions => $"{V1}/me/extensions";
        public static string UserExtensionByName(string name) => $"{V1}/me/extensions/{Uri.EscapeDataString(name)}";

        // User and Groups endpoints
        
        public static string UpdatePresence => $"{V1}/me/presence/setPresence";
        public static string UpdateMe => $"{V1}/me";
        public static string Users => $"{V1}/users?$select=id,displayName,jobTitle,department&$top=10";
        public static string UserPhoto => $"{V1}/me/photo/$value";
        public static string MemberOf => $"{V1}/me/memberOf";
        public static string Groups => $"{V1}/groups";
        public static string GroupById(string groupId) => $"{V1}/groups/{Uri.EscapeDataString(groupId)}";
        public static string GroupMembers(string groupId) => $"{V1}/groups/{Uri.EscapeDataString(groupId)}/members";
        public static string RemoveMemberRef(string groupId, string userId) => $"{V1}/groups/{Uri.EscapeDataString(groupId)}/members/{Uri.EscapeDataString(userId)}/$ref";



        // SharePoint sites drives
        public static string SiteDrive(string siteId) => $"{V1}/sites/{siteId}/drive/root/children";
        public static string SiteLists(string siteId) => $"{V1}/sites/{siteId}/lists";
        public static string SiteListItems(string siteId, string listId) => $"{V1}/sites/{siteId}/lists/{listId}/items";


        /// <summary>
        /// Generates a list of read endpoints for the specified date and feature set.
        /// </summary>
        public static IEnumerable<string> ReadEndpoints(bool extended)
        {
            DateTimeOffset now = DateTimeOffset.Now;
            var start = now.AddDays(-15).ToUniversalTime().ToString("o");
            var end = now.AddDays(1).ToUniversalTime().ToString("o");

            var eps = new List<string>
            {
                // User profile & presence
                $"{V1}/me",
                $"{Beta}/me/profile",
                $"{V1}/me/presence",
                $"{V1}/me/people",

                // Planner  Tasks.Read 
                $"{V1}/me/planner/tasks",

                // Organization & membership
                $"{V1}/me/memberOf",
                $"{V1}/me/transitiveMemberOf",
                
                // Mail - basic
                $"{V1}/me/messages?$top=5",
                $"{V1}/me/messages?$select=id,subject,attachments&$expand=attachments&$top=3",
                $"{V1}/me/mailFolders",
                $"{V1}/me/mailFolders/Inbox/messages/delta",
                $"{V1}/me/mailFolders/SentItems/messages?$top=5",
                $"{V1}/me/outlook/masterCategories",
                $"{V1}/me/messages?$expand=attachments&$top=3",
                
                // Contacts
                $"{V1}/me/contacts",
                $"{V1}/me/contactFolders",
                
                // OneDrive - basic
                $"{V1}/me/drive",
                $"{V1}/me/drive/quota",
                $"{V1}/me/drive/root",
                $"{V1}/me/drive/root/children?$top=10",
                $"{V1}/me/drive/recent",
                $"{V1}/me/drive/sharedWithMe",
                $"{V1}/me/drive/special",
                
                // Calendar - basic
                $"{V1}/me/calendar",
                $"{V1}/me/calendars",
                $"{V1}/me/events?$top=5",
                $"{V1}/me/calendar/calendarView?startDateTime={Uri.EscapeDataString(start)}&endDateTime={Uri.EscapeDataString(end)}",
                
                // OneNote
                $"{V1}/me/onenote/notebooks",
                $"{V1}/me/onenote/sections",
                $"{V1}/me/onenote/pages?$top=5",
                
                // To Do
                $"{V1}/me/todo/lists",
                
                // Insights
                $"{V1}/me/insights/used",
                $"{V1}/me/insights/trending",
                
                // SharePoint sites
                $"{V1}/sites?search=*",
                $"{V1}/sites?$top=5",
                
                // Extensions
                $"{V1}/me/extensions"
            };

            if (extended)
            {
                eps.Add($"{V1}/me/settings");

                eps.Add($"{V1}/me/licenseDetails");
                // may not exist for all users
                eps.Add($"{Beta}/communications/getPresencesByUserId");

                eps.Add($"{V1}/me/messages?$search=\"important\"&$top=5");

                eps.Add($"{V1}/me/calendar/calendarPermissions");

                eps.Add($"{V1}/me/onenote/pages?$orderby=lastModifiedDateTime desc&$top=5");
                // Organization hierarchy - may not exist for all users
                eps.Add($"{V1}/me/manager");
                eps.Add($"{V1}/me/directReports");
                
                // Directory - requires higher permissions
                eps.Add($"{V1}/users?$select=id,displayName,jobTitle&$top=10");
                
                // Contacts - expanded query (more data)
                eps.Add($"{V1}/me/contactFolders?$expand=contacts");
                
                // Mail - filtered queries (more complex)
                eps.Add($"{V1}/me/mailFolders/Inbox/messages?$filter=isRead eq false&$top=5");
                
                // OneDrive - additional operations
                eps.Add($"{V1}/me/drive/activities?$top=10");
                eps.Add($"{V1}/me/drive/special/approot");
                eps.Add($"{V1}/me/drive/search(q='{_rng.Next(1000, 9999)}')?$top=5");
                
                // Calendar - additional operations
                eps.Add($"{V1}/me/calendarGroups");
                
                // User photo - binary download (bandwidth intensive)
                eps.Add($"{V1}/me/photos/48x48/$value");
                
                // Teams - requires Team.ReadBasic.All permission (auto-ignore if no permission)
                eps.Add($"{V1}/me/joinedTeams");
                
                // Following endpoints need dynamic IDs - commented for future dynamic implementation:
                // eps.Add($"{V1}/me/todo/lists/{listId}/tasks");
                // eps.Add($"{V1}/me/drive/items/{itemId}/versions");
                // eps.Add($"{V1}/me/calendars/{calendarId}/events");
            }

            return eps;
        }
    }

    // ============== OAuth Token Management ==============

    /// <summary>
    /// Refreshes tokens for all configured accounts and persists the new refresh tokens.
    /// Returns false if any fatal error occurs (e.g., invalid client secret or expired refresh token).
    /// </summary>
    private static async Task<bool> RefreshTokensAsync(Config cfg, bool loadedFromEnv)
    {
        bool anyFatal = false;

        for (int i = 0; i < cfg.Accounts.Count; i++)
        {
            var a = cfg.Accounts[i];
            try
            {
                var body = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("client_id", a.ClientId),
                    new KeyValuePair<string, string>("client_secret", a.ClientSecret ?? ""),
                    new KeyValuePair<string, string>("grant_type", "refresh_token"),
                    new KeyValuePair<string, string>("refresh_token", a.RefreshToken),
                });

                using var resp = await _http.PostAsync($"https://login.microsoftonline.com/common/oauth2/v2.0/token", body);
                var txt = await resp.Content.ReadAsStringAsync();

                if (!resp.IsSuccessStatusCode)
                {
                    Console.WriteLine($" ***ERROR*** Failed to refresh account #{i + 1}: {txt}");
                    // Check for fatal errors requiring manual intervention
                    if (txt.Contains("AADSTS7000222") || txt.Contains("AADSTS7000215") || 
                        txt.Contains("invalid_grant") || txt.Contains("9002313"))
                        anyFatal = true;
                    continue;
                }

                // Parse response using source generator context
                var token = JsonSerializer.Deserialize<TokenResponse>(txt, ConfigContext.Default.TokenResponse);
                if (token == null || string.IsNullOrWhiteSpace(token.RefreshToken))
                {
                    Console.WriteLine($" ***WARN*** Account #{i + 1} did not return a new refresh_token.");
                    continue;
                }

                // Important: Replace old refresh_token with new one (rolling refresh)
                a.RefreshToken = token.RefreshToken;
                Console.WriteLine($" [OK] Account #{i + 1} refresh_token updated (length {a.RefreshToken.Length}).");
            }
            catch (Exception ex)
            {
                Console.WriteLine($" ***ERROR*** Account #{i + 1} refresh exception: {ex.Message}");
                anyFatal = true;
            }
        }

        // Persist updated tokens back to source
        if (loadedFromEnv)
        {
            var oneLine = JsonSerializer.Serialize(cfg.Accounts, ConfigContext.Default.ListAccountConfig);
            var ok = await UpsertGitHubSecretAsync("ACCOUNTS_JSON", oneLine);
            if (!ok)
            {
                Console.WriteLine(" [FATAL] Refresh workflow failed: unable to update repository secret. Verify PAT validity, scopes and repo selection.");
                Environment.Exit(1); // Fail GitHub Actions to alert manual intervention
                return false;
            }
            Console.WriteLine($" [INFO] Updated ACCOUNTS_JSON in GitHub Secrets.");
        }
        else
        {
            var configPath = GetSourceFilePath("Config.json");
            // Update entire config (ensuring Accounts are written back)
            await File.WriteAllTextAsync(configPath, 
                JsonSerializer.Serialize(cfg, ConfigContext.Default.Config), Encoding.UTF8);
            Console.WriteLine($" [INFO] Updated Config.json: {configPath}");
        }

        if (anyFatal)
        {
            Console.WriteLine(" ***FATAL*** Detected expired/invalid client secret or refresh token. Please update credentials or re-authorize.");
            Environment.Exit(1); // Fail GitHub Actions to alert manual intervention
        }

        return !anyFatal;
    }

    /// <summary>
    /// Obtains an access token using the refresh token from the account configuration.
    /// </summary>
    private static async Task<string> GetAccessTokenAsync(Config.AccountConfig a)
    {
        try
        {
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type","refresh_token"),
                new KeyValuePair<string, string>("refresh_token", a.RefreshToken),
                new KeyValuePair<string, string>("client_id", a.ClientId),
                new KeyValuePair<string, string>("client_secret", a.ClientSecret),
                new KeyValuePair<string, string>("redirect_uri", EP.RedirectUri)
            });

            var resp = await _http.PostAsync(EP.TokenUrl, content);
            var body = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode)
            {
                Console.WriteLine($" [ERROR] Failed to obtain token: {resp.StatusCode} {body}");
                return string.Empty;
            }

            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("access_token", out var t) ? (t.GetString() ?? "") : "";
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [ERROR] GetAccessToken exception: {ex.Message}");
            return string.Empty;
        }
    }

    // ============== Read Mode Operations ==============

    /// <summary>
    /// Executes read mode: performs GET requests to various Graph API endpoints.
    /// This mode does not modify any data.
    /// </summary>
    private static async Task RunReadModeAsync(string token)
    {
        Console.WriteLine(" [INFO] Read mode started.");
        var rd = _cfg?.Features?.Read ?? new Config.FeaturesConfig.ReadFeatures();

        var endpoints = EP.ReadEndpoints(_cfg?.Features?.Read?.UseExtendedApis ?? true).ToList();
        Shuffle(endpoints);

        int ok = 0, fail = 0;

        int readCount = Math.Clamp(_rng.Next(rd.TaskMin,  endpoints.Count), 1, endpoints.Count);
        foreach (var url in endpoints.Take(readCount))
        {
            if (await TryGetAsync(url, token)) ok++; else fail++;
            await DelayAsync(_cfg?.Run?.ApiDelay);
        }

        Console.WriteLine($" [INFO] Read mode completed. Success: {ok}, Failed: {fail}.");
    }

    /// <summary>
    /// Attempts to perform a GET request with retry logic for transient errors.
    /// </summary>
    private static async Task<bool> TryGetAsync(string url, string token)
    {
        for (int attempt = 1; attempt <= 4; attempt++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            try
            {
                using var resp = await _http.SendAsync(req);

                if (resp.IsSuccessStatusCode)
                {
                    Console.WriteLine($" [OK] GET {url}");
                    return true;
                }

                // Handle rate limiting (429 Too Many Requests)
                if ((int)resp.StatusCode == 429)
                {
                    var retry = GetRetryAfterSeconds(resp);
                    Console.WriteLine($" [WARN] 429 Too Many Requests, waiting {retry}s before retry.");
                    await Task.Delay(TimeSpan.FromSeconds(retry));
                    continue;
                }

                // Don't retry 4xx errors (except timeout)
                if ((int)resp.StatusCode >= 400 && (int)resp.StatusCode < 500 && 
                    resp.StatusCode != HttpStatusCode.RequestTimeout)
                {
                    Console.WriteLine($" [FAIL] GET {url} => {(int)resp.StatusCode} {resp.ReasonPhrase}");
                    return false;
                }

                Console.WriteLine($" [WARN] GET {url} => {(int)resp.StatusCode}, attempting retry.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($" [WARN] GET {url} exception: {ex.Message}, attempting retry.");
            }

            await DelayAsync(_cfg?.Run?.ApiDelay);
        }

        return false;
    }

    // ============== Write Mode Operations ==============

    /// <summary>
    /// Sends an email using Microsoft Graph Send Mail API.
    /// </summary>
    private static async Task SendEmailAsync(string token, string to, string subject, string body)
    {
        var payload = new
        {
            message = new
            {
                subject,
                body = new { contentType = "Text", content = body },
                toRecipients = new[]
                {
                    new { emailAddress = new { address = to } }
                }
            },
            saveToSentItems = false
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, EP.SendMail);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        req.Content = JsonContent(payload);

        using var resp = await _http.SendAsync(req);
        if (!resp.IsSuccessStatusCode)
        {
            var text = await resp.Content.ReadAsStringAsync();
            Console.WriteLine($" [WARN] Failed to send email: {resp.StatusCode} {text}");
        }
    }

    /// <summary>
    /// Executes write mode: performs various create/update/delete operations across Graph API.
    /// All created resources are cleaned up immediately after creation.
    /// </summary>
    private static async Task RunWriteModeAsync(string token, string prefix)
    {
        Console.WriteLine(" [INFO] Write mode started.");

        var wf = _cfg?.Features?.Write ?? new Config.FeaturesConfig.WriteFeatures();
        var ops = new List<Func<string, string, Task>>();

        // Register enabled write operations
        if (wf.UploadRandomFile) ops.Add(UploadRandomFileAsync);
        if (wf.Excel) ops.Add(ExcelWorkbookAndTableAsync);
        if (wf.Todo) ops.Add(TodoListAndTaskAsync);
        if (wf.CalendarEvent) ops.Add(CalendarEventRoundtripAsync);
        if (wf.Contacts) ops.Add(ContactRoundtripAsync);
        if (wf.MailDraft) ops.Add(MailDraftRoundtripAsync);
        if (wf.MailFolder) ops.Add(MailFolderRoundtripAsync);
        if (wf.MailRule) ops.Add(MailRuleRoundtripAsync);
        if (wf.OneNotePage) ops.Add(OneNotePageRoundtripAsync);
        if (wf.DriveFolderWithShareLink) ops.Add(DriveFolderFileShareRoundtripAsync);
        if (wf.UserOpenExtension) ops.Add(UserOpenExtensionRoundtripAsync);
        if (wf.GroupJoin) ops.Add(GroupJoinRoundtripAsync);
        if (wf.MailForwardReply) ops.Add(MailForwardReplyRoundtripAsync);
        if (wf.FileCopyMove) ops.Add(FileCopyMoveRoundtripAsync);
        if (wf.CalendarEventResponse) ops.Add(CalendarEventResponseRoundtripAsync);
        if (wf.TaskCompletion) ops.Add(TaskCompletionRoundtripAsync);

        Shuffle(ops);

        int writeCount = Math.Clamp(_rng.Next(wf.TaskMin, ops.Count), 1, ops.Count);

        // Execute up to 4 write operations per round to minimize mutual interference
        foreach (var op in ops.Take(writeCount))
        {
            try { await op(token, prefix); }
            catch (Exception ex) { Console.WriteLine($" [ERROR] Write operation exception: {ex.Message}"); }
            await DelayAsync(_cfg?.Run?.ApiDelay);
        }

        Console.WriteLine(" [INFO] Write mode completed.");
    }

    // ============== OneDrive Write Operations ==============

    /// <summary>
    /// OneDrive: Upload a small file and immediately delete it (self-cleanup).
    /// </summary>
    private static async Task UploadRandomFileAsync(string token, string prefix)
    {
        var fileName = $"{prefix}_{DateTimeOffset.Now:yyyyMMdd_HHmmss}_{_rng.Next(1000, 9999)}.txt";
        var bytes = Encoding.UTF8.GetBytes($"Hello Graph {Guid.NewGuid()} at {DateTimeOffset.Now:o}");

        using var req = new HttpRequestMessage(HttpMethod.Put, EP.UploadRootContent(fileName));
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        req.Content = new ByteArrayContent(bytes);
        req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        using var resp = await _http.SendAsync(req);
        if (!resp.IsSuccessStatusCode)
        {
            Console.WriteLine($" [FAIL] Upload {fileName} failed: {resp.StatusCode}");
            return;
        }

        var text = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(text);
        string? id = doc.RootElement.TryGetProperty("id", out var p) ? p.GetString() : null;

        if (!string.IsNullOrWhiteSpace(id))
        {
            using var dreq = new HttpRequestMessage(HttpMethod.Delete, EP.DeleteDriveItem(id!));
            dreq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            await _http.SendAsync(dreq);
        }

        Console.WriteLine($" [OK] Uploaded and deleted {fileName}");
    }

    // ============== Excel Write Operations ==============

    /// <summary>
    /// Excel: Load template from config -> Upload -> Create table -> Write data -> Delete workbook.
    /// </summary>
    private static async Task ExcelWorkbookAndTableAsync(string token, string prefix)
    {
        var base64 = _cfg?.Assets?.Excel?.MinimalWorkbookBase64;
        if (string.IsNullOrWhiteSpace(base64))
        {
            Console.WriteLine(" [INFO] No Excel template provided, skipping Excel workflow.");
            return;
        }

        byte[] bytes;
        try { bytes = Convert.FromBase64String(base64); }
        catch { Console.WriteLine(" [WARN] Invalid Excel template Base64, skipping."); return; }

        var name = $"{prefix}_{DateTimeOffset.Now:yyyyMMdd_HHmmss}_{_rng.Next(1000, 9999)}.xlsx";

        // Upload workbook
        string? itemId = null;
        using (var req = new HttpRequestMessage(HttpMethod.Put, EP.UploadRootContent(name)))
        {
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Content = new ByteArrayContent(bytes);
            req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");

            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) 
            { 
                Console.WriteLine($" [FAIL] Upload workbook failed: {resp.StatusCode} {text}"); 
                return; 
            }

            using var doc = JsonDocument.Parse(text);
            itemId = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;
            if (string.IsNullOrWhiteSpace(itemId)) 
            { 
                Console.WriteLine(" [FAIL] Workbook response has no id."); 
                return; 
            }
        }

        try
        {
            await DelayAsync(_cfg?.Run?.ApiDelay);

            // Create worksheet
            var wsName = "SheetCYKJ";
            var wsBody = new { name = wsName };
            using (var wsReq = new HttpRequestMessage(HttpMethod.Post, EP.ExcelWorksheets(itemId!)))
            {
                wsReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                wsReq.Content = JsonContent(wsBody);
                using var wsResp = await _http.SendAsync(wsReq);
                if (!wsResp.IsSuccessStatusCode) 
                { 
                    Console.WriteLine($" [FAIL] Create worksheet failed: {wsResp.StatusCode}"); 
                    return; 
                }
            }

            await DelayAsync(_cfg?.Run?.ApiDelay);

            // Create table
            var tblBody = new { address = "SheetCYKJ!A1:B1", hasHeaders = true };
            string? tableId = null;
            using (var tReq = new HttpRequestMessage(HttpMethod.Post, EP.ExcelTablesAdd(itemId!, wsName)))
            {
                tReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                tReq.Content = JsonContent(tblBody);
                using var tResp = await _http.SendAsync(tReq);
                var tText = await tResp.Content.ReadAsStringAsync();
                if (!tResp.IsSuccessStatusCode) 
                { 
                    Console.WriteLine($" [FAIL] Create table failed: {tResp.StatusCode} {tText}"); 
                    return; 
                }

                using var tDoc = JsonDocument.Parse(tText);
                tableId = tDoc.RootElement.TryGetProperty("id", out var tip) ? tip.GetString() : null;
                if (string.IsNullOrWhiteSpace(tableId)) 
                { 
                    Console.WriteLine(" [FAIL] Table response has no id."); 
                    return; 
                }
            }

            await DelayAsync(_cfg?.Run?.ApiDelay);

            // Write data rows
            var rowsPayload = new
            {
                values = new List<List<object>>
                {
                    new List<object>{ "Header1", "Header2" },
                    new List<object>{ _rng.Next(1,100), _rng.Next(100,1000) },
                    new List<object>{ _rng.Next(1,100), _rng.Next(100,1000) }
                }
            };

            using var rReq = new HttpRequestMessage(HttpMethod.Post, EP.ExcelTableRowsAdd(itemId!, tableId!));
            rReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            rReq.Content = JsonContent(rowsPayload);
            using var rResp = await _http.SendAsync(rReq);

            Console.WriteLine(rResp.IsSuccessStatusCode ? 
                " [OK] Excel write completed." : 
                $" [FAIL] Excel write failed: {rResp.StatusCode}");
        }
        finally
        {
            // Delete workbook
            using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.DeleteDriveItem(itemId!));
            dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            await _http.SendAsync(dReq);
        }
    }

    // ============== To Do Write Operations ==============

    /// <summary>
    /// To Do: Create list -> Create task -> Delete list.
    /// </summary>
    private static async Task TodoListAndTaskAsync(string token, string prefix)
    {
        string? listId = null;
        try
        {
            var listName = $"{prefix}_List_{_rng.Next(10000, 99999)}";
            using (var lReq = new HttpRequestMessage(HttpMethod.Post, EP.TodoLists))
            {
                lReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                lReq.Content = JsonContent(new { displayName = listName });
                using var lResp = await _http.SendAsync(lReq);
                var lText = await lResp.Content.ReadAsStringAsync();
                if (!lResp.IsSuccessStatusCode) 
                { 
                    Console.WriteLine($" [FAIL] Create ToDo list failed: {lResp.StatusCode} {lText}"); 
                    return; 
                }

                using var lDoc = JsonDocument.Parse(lText);
                listId = lDoc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;
                if (string.IsNullOrWhiteSpace(listId)) 
                { 
                    Console.WriteLine(" [FAIL] ToDo list response has no id"); 
                    return; 
                }
            }

            var taskTitle = $"{prefix}_Task_{_rng.Next(10000, 99999)}";
            using (var tReq = new HttpRequestMessage(HttpMethod.Post, EP.TodoTasks(listId!)))
            {
                tReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                tReq.Content = JsonContent(new { title = taskTitle });
                using var tResp = await _http.SendAsync(tReq);
                if (!tResp.IsSuccessStatusCode) 
                    Console.WriteLine($" [WARN] Create task failed: {tResp.StatusCode}");
            }

            Console.WriteLine(" [OK] ToDo list creation completed.");
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(listId))
            {
                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.TodoListById(listId!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
            }
        }
    }

    private static async Task TaskCompletionRoundtripAsync(string token, string prefix)
    {
        string? listId = null, taskId = null;
        try
        {
            // 创建待办列表
            var listName = $"{prefix}TaskTest_{_rng.Next(10000, 99999)}";
            using var listReq = new HttpRequestMessage(HttpMethod.Post, EP.TodoLists);
            listReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            listReq.Content = JsonContent(new { displayName = listName });
            using var listResp = await _http.SendAsync(listReq);
            var listText = await listResp.Content.ReadAsStringAsync();
            
            if (!listResp.IsSuccessStatusCode)
            {
                Console.WriteLine($"FAIL: Create task list failed: {listResp.StatusCode}");
                return;
            }
            
            using var listDoc = JsonDocument.Parse(listText);
            listId = listDoc.RootElement.TryGetProperty("id", out var lid) ? lid.GetString() : null;
            
            if (string.IsNullOrWhiteSpace(listId))
            {
                Console.WriteLine("FAIL: List has no id");
                return;
            }
            
            await DelayAsync(_cfg?.Run?.ApiDelay);
            
            // 创建任务
            var taskTitle = $"{prefix}Task_{_rng.Next(10000, 99999)}";
            using var taskReq = new HttpRequestMessage(HttpMethod.Post, EP.TodoTasks(listId!));
            taskReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            taskReq.Content = JsonContent(new { title = taskTitle });
            using var taskResp = await _http.SendAsync(taskReq);
            var taskText = await taskResp.Content.ReadAsStringAsync();
            
            if (!taskResp.IsSuccessStatusCode)
            {
                Console.WriteLine($"FAIL: Create task failed: {taskResp.StatusCode}");
                return;
            }
            
            using var taskDoc = JsonDocument.Parse(taskText);
            taskId = taskDoc.RootElement.TryGetProperty("id", out var tid) ? tid.GetString() : null;
            
            if (string.IsNullOrWhiteSpace(taskId))
            {
                Console.WriteLine("FAIL: Task has no id");
                return;
            }
            
            await DelayAsync(_cfg?.Run?.ApiDelay);
            
            // 标记任务为完成
            var completeBody = new { status = "completed" };
            using var completeReq = new HttpRequestMessage(HttpMethod.Patch, EP.CompleteTask(listId!, taskId!));
            completeReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            completeReq.Content = JsonContent(completeBody);
            using var completeResp = await _http.SendAsync(completeReq);
            
            Console.WriteLine(completeResp.IsSuccessStatusCode 
                ? "OK: Task completion test completed." 
                : $"WARN: Task completion failed: {completeResp.StatusCode}");
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(listId))
            {
                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.TodoListById(listId!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
            }
        }
    }


    // ============== Calendar Write Operations ==============

    /// <summary>
    /// Calendar: Create event -> Delete event.
    /// </summary>
    private static async Task CalendarEventRoundtripAsync(string token, string prefix)
    {
        string? eventId = null;
        try
        {
            var subject = $"{prefix}_Event_{_rng.Next(10000, 99999)}";
            var start = DateTimeOffset.Now.AddMinutes(5).ToUniversalTime();
            var end = start.AddMinutes(30);

            var body = new
            {
                subject,
                start = new { dateTime = start.ToString("o"), timeZone = "UTC" },
                end = new { dateTime = end.ToString("o"), timeZone = "UTC" },
                location = new { displayName = "Virtual" }
            };

            using var req = new HttpRequestMessage(HttpMethod.Post, EP.Events);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Content = JsonContent(body);

            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode)
            {
                Console.WriteLine($" [FAIL] Create event failed: {resp.StatusCode} {text}");
                return;
            }

            using var doc = JsonDocument.Parse(text);
            eventId = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;

            Console.WriteLine(string.IsNullOrWhiteSpace(eventId) ?
                " [FAIL] Event response has no id" :
                " [OK] Event creation completed.");
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(eventId))
            {
                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.EventById(eventId!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
            }
        }
    }
    private static async Task CalendarEventResponseRoundtripAsync(string token, string prefix)
    {
        string? eventId = null;
        try
        {
            // 创建事件
            var subject = $"{prefix}ResponseTest_{_rng.Next(10000, 99999)}";
            var start = DateTimeOffset.Now.AddMinutes(5).ToUniversalTime();
            var end = start.AddMinutes(30);
            
            var body = new
            {
                subject,
                start = new { dateTime = start.ToString("o"), timeZone = "UTC" },
                end = new { dateTime = end.ToString("o"), timeZone = "UTC" },
                location = new { displayName = "Virtual" }
            };
            
            using var req = new HttpRequestMessage(HttpMethod.Post, EP.Events);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Content = JsonContent(body);
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            
            if (!resp.IsSuccessStatusCode)
            {
                Console.WriteLine($"FAIL: Create event failed: {resp.StatusCode}");
                return;
            }
            
            using var doc = JsonDocument.Parse(text);
            eventId = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;
            
            if (string.IsNullOrWhiteSpace(eventId))
            {
                Console.WriteLine("FAIL: Event has no id");
                return;
            }
            
            await DelayAsync(_cfg?.Run?.ApiDelay);
            
            // 接受事件
            var acceptBody = new
            {
                comment = "Accepted via automation",
                sendResponse = false
            };
            
            using var acceptReq = new HttpRequestMessage(HttpMethod.Post, EP.AcceptEvent(eventId!));
            acceptReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            acceptReq.Content = JsonContent(acceptBody);
            using var acceptResp = await _http.SendAsync(acceptReq);
            
            Console.WriteLine(acceptResp.IsSuccessStatusCode 
                ? "OK: Event acceptance completed." 
                : $"WARN: Event accept failed: {acceptResp.StatusCode}");
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(eventId))
            {
                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.EventById(eventId!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
            }
        }
    }


    // ============== Contacts Write Operations ==============

    /// <summary>
    /// Contacts: Create contact -> Delete contact.
    /// </summary>
    private static async Task ContactRoundtripAsync(string token, string prefix)
    {
        string? id = null;
        try
        {
            var displayName = $"{prefix}_Contact_{_rng.Next(10000, 99999)}";
            var body = new
            {
                displayName,
                givenName = prefix,
                emailAddresses = new[] { new { address = "foo@example.com", name = "Foo" } }
            };

            using var req = new HttpRequestMessage(HttpMethod.Post, EP.Contacts);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Content = JsonContent(body);

            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode)
            {
                Console.WriteLine($" [FAIL] Create contact failed: {resp.StatusCode} {text}");
                return;
            }

            using var doc = JsonDocument.Parse(text);
            id = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;

            Console.WriteLine(string.IsNullOrWhiteSpace(id) ?
                " [FAIL] Contact response has no id" :
                " [OK] Contact creation completed.");
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(id))
            {
                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.ContactById(id!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
            }
        }
    }

    // ============== Mail Write Operations ==============

    /// <summary>
    /// Mail: Create draft -> Delete draft.
    /// </summary>
    private static async Task MailDraftRoundtripAsync(string token, string prefix)
    {
        string? id = null;
        try
        {
            var subject = $"{prefix}_Draft_{_rng.Next(10000, 99999)}";
            var body = new 
            { 
                subject, 
                body = new { contentType = "Text", content = "Draft content" }, 
                toRecipients = new object[] { } 
            };

            using var req = new HttpRequestMessage(HttpMethod.Post, EP.CreateMessage);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Content = JsonContent(body);

            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) 
            { 
                Console.WriteLine($" [FAIL] Create draft failed: {resp.StatusCode} {text}"); 
                return; 
            }

            using var doc = JsonDocument.Parse(text);
            id = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;

            Console.WriteLine(string.IsNullOrWhiteSpace(id) ? 
                " [FAIL] Draft response has no id" : 
                " [OK] Draft creation completed.");
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(id))
            {
                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.MessageById(id!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
            }
        }
    }

    /// <summary>
    /// Mail: Create folder -> Delete folder.
    /// </summary>
    private static async Task MailFolderRoundtripAsync(string token, string prefix)
    {
        string? id = null;
        try
        {
            var name = $"{prefix}_Folder_{_rng.Next(10000, 99999)}";
            var body = new { displayName = name };

            using var req = new HttpRequestMessage(HttpMethod.Post, EP.MailFolders);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Content = JsonContent(body);

            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) 
            { 
                Console.WriteLine($" [FAIL] Create mail folder failed: {resp.StatusCode} {text}"); 
                return; 
            }

            using var doc = JsonDocument.Parse(text);
            id = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;

            Console.WriteLine(string.IsNullOrWhiteSpace(id) ? 
                " [FAIL] Folder response has no id" : 
                " [OK] Mail folder creation completed.");
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(id))
            {
                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.MailFolderById(id!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
            }
        }
    }

    /// <summary>
    /// Mail: Create inbox rule -> Delete rule.
    /// </summary>
    private static async Task MailRuleRoundtripAsync(string token, string prefix)
    {
        string? id = null;
        try
        {
            var displayName = $"{prefix}_Rule_{_rng.Next(10000, 99999)}";
            var body = new
            {
                displayName,
                sequence = 1,
                isEnabled = true,
                conditions = new { bodyOrSubjectContains = new[] { "graph" } },
                actions = new { markAsRead = true, stopProcessingRules = true }
            };

            using var req = new HttpRequestMessage(HttpMethod.Post, EP.InboxRules);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Content = JsonContent(body);

            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) 
            { 
                Console.WriteLine($" [WARN] Create mail rule failed: {resp.StatusCode} {text}"); 
                return; 
            }

            using var doc = JsonDocument.Parse(text);
            id = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;

            if (!string.IsNullOrWhiteSpace(id)) 
                Console.WriteLine(" [OK] Mail rule creation completed.");
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(id))
            {
                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.InboxRuleById(id!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
            }
        }
    }

    private static async Task MailForwardReplyRoundtripAsync(string token, string prefix)
    {
        string? messageId = null;
        try
        {
            // 首先创建一个草稿邮件
            var subject = $"{prefix}ForwardTest_{_rng.Next(10000, 99999)}";
            var draftBody = new
            {
                subject,
                body = new { contentType = "Text", content = "Original message" },
                toRecipients = Array.Empty<object>()
            };
            
            using var draftReq = new HttpRequestMessage(HttpMethod.Post, EP.CreateMessage);
            draftReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            draftReq.Content = JsonContent(draftBody);
            using var draftResp = await _http.SendAsync(draftReq);
            var draftText = await draftResp.Content.ReadAsStringAsync();
            
            if (!draftResp.IsSuccessStatusCode)
            {
                Console.WriteLine($"FAIL: Create draft for forward test failed: {draftResp.StatusCode}");
                return;
            }
            
            using var doc = JsonDocument.Parse(draftText);
            messageId = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;
            
            if (string.IsNullOrWhiteSpace(messageId))
            {
                Console.WriteLine("FAIL: Draft message has no id");
                return;
            }
            
            await DelayAsync(_cfg?.Run?.ApiDelay);
            
            // 测试转发操作 (注意:转发草稿可能不被允许,仅作示例)
            var forwardBody = new
            {
                comment = "Forwarding test",
                toRecipients = new[] { new { emailAddress = new { address = "test@example.com" } } }
            };
            
            using var fwdReq = new HttpRequestMessage(HttpMethod.Post, EP.ForwardMessage(messageId!));
            fwdReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            fwdReq.Content = JsonContent(forwardBody);
            using var fwdResp = await _http.SendAsync(fwdReq);
            
            Console.WriteLine(fwdResp.IsSuccessStatusCode 
                ? "OK: Mail forward test completed." 
                : $"WARN: Mail forward failed: {fwdResp.StatusCode}");
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(messageId))
            {
                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.MessageById(messageId!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
            }
        }
    }

    // ============== OneNote Write Operations ==============

    /// <summary>
    /// OneNote: Create page -> Delete page.
    /// </summary>
    private static async Task OneNotePageRoundtripAsync(string token, string prefix)
    {
        string? id = null;
        try
        {
            var title = $"{prefix}_OneNote_{_rng.Next(10000, 99999)}";
            var html = $"<!DOCTYPE html><html><head><title>{System.Net.WebUtility.HtmlEncode(title)}</title></head>" +
                       $"<body><p>Created at {DateTimeOffset.Now:o}</p></body></html>";

            using var req = new HttpRequestMessage(HttpMethod.Post, EP.OneNotePages);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Content = new StringContent(html, Encoding.UTF8, "application/xhtml+xml");

            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode)
            {
                Console.WriteLine($" [WARN] Create OneNote page failed: {resp.StatusCode} {text}");
                return;
            }

            using var doc = JsonDocument.Parse(text);
            id = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;

            if (!string.IsNullOrWhiteSpace(id))
                Console.WriteLine(" [OK] OneNote page creation completed.");
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(id))
            {
                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.OneNotePageById(id!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
            }
        }
    }

    // ============== Drive Advanced Write Operations ==============

    /// <summary>
    /// Drive: Create folder -> Upload file to folder -> Create share link -> Delete permission -> Delete folder.
    /// </summary>
    private static async Task DriveFolderFileShareRoundtripAsync(string token, string prefix)
    {
        string? folderId = null;
        try
        {
            // Create folder
            var folderName = $"{prefix}_Dir_{_rng.Next(10000, 99999)}";
            var folderBody = new Dictionary<string, object>
            {
                ["name"] = folderName,
                ["folder"] = new Dictionary<string, object>(),
                ["@microsoft.graph.conflictBehavior"] = "rename"
            };

            using (var req = new HttpRequestMessage(HttpMethod.Post, EP.CreateFolderUnderRoot))
            {
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                req.Content = JsonContent(folderBody);
                using var resp = await _http.SendAsync(req);
                var text = await resp.Content.ReadAsStringAsync();
                if (!resp.IsSuccessStatusCode) 
                { 
                    Console.WriteLine($" [WARN] Create folder failed: {resp.StatusCode} {text}"); 
                    return; 
                }

                using var doc = JsonDocument.Parse(text);
                folderId = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;
                if (string.IsNullOrWhiteSpace(folderId)) 
                { 
                    Console.WriteLine(" [FAIL] Folder response has no id"); 
                    return; 
                }
            }

            await DelayAsync(_cfg?.Run?.ApiDelay);

            // Upload file to folder
            var fileName = $"{prefix}_Inner_{_rng.Next(10000, 99999)}.txt";
            using (var uReq = new HttpRequestMessage(HttpMethod.Put, EP.UploadUnderItem(folderId!, fileName)))
            {
                uReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                var bytes = Encoding.UTF8.GetBytes("hello");
                uReq.Content = new ByteArrayContent(bytes);
                uReq.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

                using var uResp = await _http.SendAsync(uReq);
                if (!uResp.IsSuccessStatusCode) 
                    Console.WriteLine($" [WARN] Upload file to folder failed: {uResp.StatusCode}");
            }

            await DelayAsync(_cfg?.Run?.ApiDelay);

            // Create share link, then delete permission
            string? permId = null;
            using (var sReq = new HttpRequestMessage(HttpMethod.Post, EP.DriveItemCreateLink(folderId!)))
            {
                sReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                var linkBody = new { type = "view", scope = "anonymous" };
                sReq.Content = JsonContent(linkBody);

                using var sResp = await _http.SendAsync(sReq);
                var sText = await sResp.Content.ReadAsStringAsync();
                if (sResp.IsSuccessStatusCode)
                {
                    using var sDoc = JsonDocument.Parse(sText);
                    if (sDoc.RootElement.TryGetProperty("id", out var pid)) 
                        permId = pid.GetString();
                }
                else
                {
                    Console.WriteLine($" [WARN] Create share link failed: {sResp.StatusCode} {sText}");
                }
            }

            if (!string.IsNullOrWhiteSpace(permId))
            {
                using var pDel = new HttpRequestMessage(HttpMethod.Delete, EP.DriveItemPermissions(folderId!, permId!));
                pDel.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(pDel);
            }

            Console.WriteLine(" [OK] Drive folder and share link operations completed.");
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(folderId))
            {
                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.DeleteDriveItem(folderId!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
            }
        }
    }

    private static async Task FileCopyMoveRoundtripAsync(string token, string prefix)
    {
        string? sourceId = null, targetId = null;
        try
        {
            // 创建源文件
            var fileName = $"{prefix}CopySource_{DateTimeOffset.Now:yyyyMMddHHmmss}_{_rng.Next(1000, 9999)}.txt";
            var bytes = Encoding.UTF8.GetBytes($"Copy test content {Guid.NewGuid()}");
            
            using var uploadReq = new HttpRequestMessage(HttpMethod.Put, EP.UploadRootContent(fileName));
            uploadReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            uploadReq.Content = new ByteArrayContent(bytes);
            uploadReq.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            using var uploadResp = await _http.SendAsync(uploadReq);
            var uploadText = await uploadResp.Content.ReadAsStringAsync();
            
            if (!uploadResp.IsSuccessStatusCode)
            {
                Console.WriteLine($"FAIL: Upload source file failed: {uploadResp.StatusCode}");
                return;
            }
            
            using var doc = JsonDocument.Parse(uploadText);
            sourceId = doc.RootElement.TryGetProperty("id", out var p) ? p.GetString() : null;
            
            if (string.IsNullOrWhiteSpace(sourceId))
            {
                Console.WriteLine("FAIL: Source file has no id");
                return;
            }
            
            await DelayAsync(_cfg?.Run?.ApiDelay);
            
            // 执行复制操作
            var copyBody = new
            {
                name = $"{prefix}CopyTarget_{_rng.Next(10000, 99999)}.txt"
            };
            
            using var copyReq = new HttpRequestMessage(HttpMethod.Post, EP.CopyDriveItem(sourceId!));
            copyReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            copyReq.Content = JsonContent(copyBody);
            using var copyResp = await _http.SendAsync(copyReq);
            
            // Copy 操作是异步的,返回202和Location header
            if ((int)copyResp.StatusCode == 202)
            {
                Console.WriteLine("OK: File copy initiated (async operation).");
                // 可以从 Location header 获取监控 URL
            }
            else
            {
                Console.WriteLine($"WARN: File copy failed: {copyResp.StatusCode}");
            }
        }
        finally
        {
            // 清理源文件
            if (!string.IsNullOrWhiteSpace(sourceId))
            {
                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.DeleteDriveItem(sourceId!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
            }
        }
    }


    // ============== User Extensions Write Operations ==============

    /// <summary>
    /// User extensions: Create extension -> Read extension -> Delete extension.
    /// </summary>
    private static async Task UserOpenExtensionRoundtripAsync(string token, string prefix)
    {
        string name = $"{prefix}.meta.{_rng.Next(10000, 99999)}";
        try
        {
            var payload = new Dictionary<string, object>
            {
                ["@odata.type"] = "microsoft.graph.openTypeExtension",
                ["extensionName"] = name,
                ["foo"] = "bar",
                ["createdAt"] = DateTimeOffset.Now.ToString("o")
            };

            using (var cReq = new HttpRequestMessage(HttpMethod.Post, EP.UserExtensions))
            {
                cReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                cReq.Content = JsonContent(payload);
                using var cResp = await _http.SendAsync(cReq);
                if (!cResp.IsSuccessStatusCode)
                {
                    Console.WriteLine($" [WARN] Create user extension failed: {cResp.StatusCode}");
                    return;
                }
            }

            // Read extension before deletion
            using (var gReq = new HttpRequestMessage(HttpMethod.Get, EP.UserExtensionByName(name)))
            {
                gReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(gReq);
            }

            Console.WriteLine(" [OK] User extension operations completed.");
        }
        finally
        {
            using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.UserExtensionByName(name));
            dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            await _http.SendAsync(dReq);
        }
    }

    // ============== Groups Write Operations ==============

    /// <summary>
    /// Group write flow: Most tenants prohibit regular users from creating groups.
    /// This method only performs memberOf read as a write simulation.
    /// Actual group creation requires admin permissions, not suitable for delegated scenarios.
    /// </summary>
    private static async Task GroupJoinRoundtripAsync(string token, string prefix)
    {
        Console.WriteLine(" [INFO] Group write only performs memberOf read (group creation requires admin permissions).");
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, EP.MemberOf);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();

            if (resp.IsSuccessStatusCode)
            {
                Console.WriteLine(" [OK] MemberOf read completed.");
            }
            else
            {
                Console.WriteLine($" [WARN] MemberOf read failed: {resp.StatusCode} {text}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [WARN] Group write exception: {ex.Message}");
        }
    }

    // ============== Cleanup Operations (All Prefixes) ==============

    /// <summary>
    /// Cleans up all resources created with the specified prefixes across all Graph API services.
    /// </summary>
    private static async Task CleanupAllPrefixesAsync(string token, List<string> prefixes)
    {
        if (prefixes == null || prefixes.Count == 0) return;

        // OneDrive cleanup
        foreach (var p in prefixes)
            await CleanupDriveByPrefixAsync(token, p);

        // Other services cleanup
        await CleanupTodoListsByPrefixesAsync(token, prefixes);
        await CleanupCalendarByPrefixesAsync(token, prefixes);
        await CleanupContactsByPrefixesAsync(token, prefixes);
        await CleanupMailDraftsByPrefixesAsync(token, prefixes);
        await CleanupMailFoldersByPrefixesAsync(token, prefixes);
        await CleanupMailRulesByPrefixesAsync(token, prefixes);
        await CleanupOneNotePagesByPrefixesAsync(token, prefixes);
        await CleanupUserExtensionsByPrefixesAsync(token, prefixes);
        await CleanupGroupMembershipByPrefixesAsync(token, prefixes);
    }

    /// <summary>
    /// Cleans up OneDrive items with the specified prefix.
    /// </summary>
    private static async Task CleanupDriveByPrefixAsync(string token, string prefix)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, EP.SearchDriveItems(prefix));
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode) 
            { 
                Console.WriteLine($" [WARN] Drive search failed: {resp.StatusCode} {text}"); 
                return; 
            }

            using var doc = JsonDocument.Parse(text);
            if (!doc.RootElement.TryGetProperty("value", out var items)) return;

            foreach (var it in items.EnumerateArray())
            {
                string name = it.TryGetProperty("name", out var np) ? (np.GetString() ?? "") : "";
                if (!StartsWithAny(name, new[] { prefix })) continue;

                string? id = it.TryGetProperty("id", out var ip) ? ip.GetString() : null;
                if (string.IsNullOrWhiteSpace(id)) continue;

                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.DeleteDriveItem(id!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
                await DelayAsync(_cfg?.Run?.ApiDelay);
            }
        }
        catch (Exception ex) 
        { 
            Console.WriteLine($" [WARN] Drive cleanup exception: {ex.Message}"); 
        }
    }

    /// <summary>
    /// Cleans up To Do lists with the specified prefixes.
    /// </summary>
    private static async Task CleanupTodoListsByPrefixesAsync(string token, List<string> prefixes)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, EP.TodoLists);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode) return;

            using var doc = JsonDocument.Parse(text);
            if (!doc.RootElement.TryGetProperty("value", out var arr)) return;

            foreach (var v in arr.EnumerateArray())
            {
                string name = v.TryGetProperty("displayName", out var np) ? (np.GetString() ?? "") : "";
                if (!StartsWithAny(name, prefixes)) continue;

                string? id = v.TryGetProperty("id", out var ip) ? ip.GetString() : null;
                if (string.IsNullOrWhiteSpace(id)) continue;

                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.TodoListById(id!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
                await DelayAsync(_cfg?.Run?.ApiDelay);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [WARN] ToDo lists cleanup exception: {ex.Message}");
        }
    }

    /// <summary>
    /// Cleans up calendar events with the specified prefixes (limited scope to reduce scanning cost).
    /// </summary>
    private static async Task CleanupCalendarByPrefixesAsync(string token, List<string> prefixes)
    {
        try
        {
            // Fetch limited events for cleanup (avoid wide-range scanning)
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{EP.Events}?$top=50");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode) return;

            using var doc = JsonDocument.Parse(text);
            if (!doc.RootElement.TryGetProperty("value", out var arr)) return;

            foreach (var v in arr.EnumerateArray())
            {
                string subject = v.TryGetProperty("subject", out var sp) ? (sp.GetString() ?? "") : "";
                if (!StartsWithAny(subject, prefixes)) continue;

                string? id = v.TryGetProperty("id", out var ip) ? ip.GetString() : null;
                if (string.IsNullOrWhiteSpace(id)) continue;

                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.EventById(id!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
                await DelayAsync(_cfg?.Run?.ApiDelay);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [WARN] Calendar cleanup exception: {ex.Message}");
        }
    }

    /// <summary>
    /// Cleans up contacts with the specified prefixes.
    /// </summary>
    private static async Task CleanupContactsByPrefixesAsync(string token, List<string> prefixes)
    {
        try
        {
            string? url = $"{EP.Contacts}?$top=50";
            while (!string.IsNullOrWhiteSpace(url))
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                using var resp = await _http.SendAsync(req);
                var text = await resp.Content.ReadAsStringAsync();

                if (!resp.IsSuccessStatusCode) break;

                using var doc = JsonDocument.Parse(text);
                if (doc.RootElement.TryGetProperty("value", out var arr))
                {
                    foreach (var v in arr.EnumerateArray())
                    {
                        string name = v.TryGetProperty("displayName", out var np) ? (np.GetString() ?? "") : "";
                        if (!StartsWithAny(name, prefixes)) continue;

                        string? id = v.TryGetProperty("id", out var ip) ? ip.GetString() : null;
                        if (string.IsNullOrWhiteSpace(id)) continue;

                        using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.ContactById(id!));
                        dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                        await _http.SendAsync(dReq);
                        await DelayAsync(_cfg?.Run?.ApiDelay);
                    }
                }

                // Handle pagination
                url = doc.RootElement.TryGetProperty("@odata.nextLink", out var link) ? link.GetString() : null;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [WARN] Contacts cleanup exception: {ex.Message}");
        }
    }

    /// <summary>
    /// Cleans up mail drafts with the specified prefixes.
    /// </summary>
    private static async Task CleanupMailDraftsByPrefixesAsync(string token, List<string> prefixes)
    {
        try
        {
            // Only cleanup drafts to avoid deleting actual emails
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{EP.CreateMessage}?$filter=isDraft eq true&$top=50");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode) return;

            using var doc = JsonDocument.Parse(text);
            if (!doc.RootElement.TryGetProperty("value", out var arr)) return;

            foreach (var v in arr.EnumerateArray())
            {
                string subject = v.TryGetProperty("subject", out var sp) ? (sp.GetString() ?? "") : "";
                if (!StartsWithAny(subject, prefixes)) continue;

                string? id = v.TryGetProperty("id", out var ip) ? ip.GetString() : null;
                if (string.IsNullOrWhiteSpace(id)) continue;

                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.MessageById(id!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
                await DelayAsync(_cfg?.Run?.ApiDelay);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [WARN] Mail drafts cleanup exception: {ex.Message}");
        }
    }

    /// <summary>
    /// Cleans up mail folders with the specified prefixes.
    /// </summary>
    private static async Task CleanupMailFoldersByPrefixesAsync(string token, List<string> prefixes)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, EP.MailFolders);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode) return;

            using var doc = JsonDocument.Parse(text);
            if (!doc.RootElement.TryGetProperty("value", out var arr)) return;

            foreach (var v in arr.EnumerateArray())
            {
                string name = v.TryGetProperty("displayName", out var np) ? (np.GetString() ?? "") : "";
                if (!StartsWithAny(name, prefixes)) continue;

                string? id = v.TryGetProperty("id", out var ip) ? ip.GetString() : null;
                if (string.IsNullOrWhiteSpace(id)) continue;

                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.MailFolderById(id!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
                await DelayAsync(_cfg?.Run?.ApiDelay);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [WARN] Mail folders cleanup exception: {ex.Message}");
        }
    }

    /// <summary>
    /// Cleans up mail rules with the specified prefixes.
    /// </summary>
    private static async Task CleanupMailRulesByPrefixesAsync(string token, List<string> prefixes)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, EP.InboxRules);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode) return;

            using var doc = JsonDocument.Parse(text);
            if (!doc.RootElement.TryGetProperty("value", out var arr)) return;

            foreach (var v in arr.EnumerateArray())
            {
                string name = v.TryGetProperty("displayName", out var np) ? (np.GetString() ?? "") : "";
                if (!StartsWithAny(name, prefixes)) continue;

                string? id = v.TryGetProperty("id", out var ip) ? ip.GetString() : null;
                if (string.IsNullOrWhiteSpace(id)) continue;

                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.InboxRuleById(id!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
                await DelayAsync(_cfg?.Run?.ApiDelay);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [WARN] Mail rules cleanup exception: {ex.Message}");
        }
    }

    /// <summary>
    /// Cleans up OneNote pages with the specified prefixes.
    /// </summary>
    private static async Task CleanupOneNotePagesByPrefixesAsync(string token, List<string> prefixes)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{EP.OneNotePages}?$top=50");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode) return;

            using var doc = JsonDocument.Parse(text);
            if (!doc.RootElement.TryGetProperty("value", out var arr)) return;

            foreach (var v in arr.EnumerateArray())
            {
                string title = v.TryGetProperty("title", out var tp) ? (tp.GetString() ?? "") : "";
                if (!StartsWithAny(title, prefixes)) continue;

                string? id = v.TryGetProperty("id", out var ip) ? ip.GetString() : null;
                if (string.IsNullOrWhiteSpace(id)) continue;

                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.OneNotePageById(id!));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
                await DelayAsync(_cfg?.Run?.ApiDelay);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [WARN] OneNote pages cleanup exception: {ex.Message}");
        }
    }

    /// <summary>
    /// Cleans up user extensions with the specified prefixes.
    /// </summary>
    private static async Task CleanupUserExtensionsByPrefixesAsync(string token, List<string> prefixes)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, EP.UserExtensions);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode) return;

            using var doc = JsonDocument.Parse(text);
            if (!doc.RootElement.TryGetProperty("value", out var arr)) return;

            foreach (var v in arr.EnumerateArray())
            {
                string id = v.TryGetProperty("id", out var ip) ? (ip.GetString() ?? "") : "";
                string? name = v.TryGetProperty("extensionName", out var en) ? en.GetString() : null;
                string key = !string.IsNullOrWhiteSpace(name) ? name! : id;

                if (!StartsWithAny(key, prefixes)) continue;

                using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.UserExtensionByName(key));
                dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(dReq);
                await DelayAsync(_cfg?.Run?.ApiDelay);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [WARN] User extensions cleanup exception: {ex.Message}");
        }
    }

    /// <summary>
    /// Cleans up group memberships with the specified prefixes.
    /// Steps:
    /// 1) GET /me/memberOf to get user's groups
    /// 2) For groups with matching prefix, call DELETE /groups/{group-id}/members/{user-id}/$ref to leave
    /// 3) GET /me to obtain user id for constructing delete endpoint
    /// Note: Only works for assigned memberships, not dynamic memberships. Not supported for personal Microsoft accounts.
    /// </summary>
    private static async Task CleanupGroupMembershipByPrefixesAsync(string token, List<string> prefixes)
    {
        try
        {
            // Step 1: Get current user id
            string? userId = null;
            using (var meReq = new HttpRequestMessage(HttpMethod.Get, $"{EP.V1}/me?$select=id"))
            {
                meReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                using var meResp = await _http.SendAsync(meReq);
                var meText = await meResp.Content.ReadAsStringAsync();

                if (!meResp.IsSuccessStatusCode)
                {
                    Console.WriteLine($" [WARN] Unable to get user id: {meResp.StatusCode} {meText}");
                    return;
                }

                using var meDoc = JsonDocument.Parse(meText);
                userId = meDoc.RootElement.TryGetProperty("id", out var uidp) ? uidp.GetString() : null;

                if (string.IsNullOrWhiteSpace(userId))
                {
                    Console.WriteLine(" [WARN] User id is empty, cannot cleanup groups.");
                    return;
                }
            }

            // Step 2: GET /me/memberOf
            using var req = new HttpRequestMessage(HttpMethod.Get, EP.MemberOf);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode)
            {
                Console.WriteLine($" [WARN] MemberOf read failed: {resp.StatusCode} {text}");
                return;
            }

            using var doc = JsonDocument.Parse(text);
            if (!doc.RootElement.TryGetProperty("value", out var arr)) return;

            int removedCount = 0;
            foreach (var item in arr.EnumerateArray())
            {
                // Only process items with @odata.type = #microsoft.graph.group
                if (item.TryGetProperty("@odata.type", out var typeEl))
                {
                    string? typeVal = typeEl.GetString();
                    if (typeVal != "#microsoft.graph.group") continue; // Skip non-group directoryObjects
                }

                string displayName = item.TryGetProperty("displayName", out var dnp) ? (dnp.GetString() ?? "") : "";
                if (!StartsWithAny(displayName, prefixes)) continue;

                string? groupId = item.TryGetProperty("id", out var gidp) ? gidp.GetString() : null;
                if (string.IsNullOrWhiteSpace(groupId)) continue;

                // Step 3: DELETE /groups/{groupId}/members/{userId}/$ref
                using var delReq = new HttpRequestMessage(HttpMethod.Delete, EP.RemoveMemberRef(groupId!, userId!));
                delReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                using var delResp = await _http.SendAsync(delReq);

                if (delResp.IsSuccessStatusCode || delResp.StatusCode == HttpStatusCode.NoContent)
                {
                    Console.WriteLine($" [OK] Left group: {displayName} (id={groupId})");
                    removedCount++;
                }
                else
                {
                    var errText = await delResp.Content.ReadAsStringAsync();
                    Console.WriteLine($" [WARN] Failed to leave group {displayName}: {delResp.StatusCode} {errText}");
                }

                await DelayAsync(_cfg?.Run?.ApiDelay);
            }

            if (removedCount > 0)
                Console.WriteLine($" [INFO] Total groups left: {removedCount}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [WARN] Groups cleanup exception: {ex.Message}");
        }
    }

    // ============== Helper Methods ==============

    /// <summary>
    /// Fisher-Yates shuffle algorithm for randomizing list order.
    /// </summary>
    private static void Shuffle<T>(IList<T> list)
    {
        for (int i = list.Count - 1; i > 0; i--)
        {
            int j = _rng.Next(i + 1);
            (list[i], list[j]) = (list[j], list[i]);
        }
    }

    /// <summary>
    /// Extracts Retry-After value from HTTP response headers for rate limiting.
    /// </summary>
    private static int GetRetryAfterSeconds(HttpResponseMessage resp)
    {
        try
        {
            if (resp.Headers.RetryAfter != null)
            {
                if (resp.Headers.RetryAfter.Delta.HasValue)
                    return Math.Max(1, (int)resp.Headers.RetryAfter.Delta.Value.TotalSeconds);

                if (resp.Headers.RetryAfter.Date.HasValue)
                {
                    var delta = resp.Headers.RetryAfter.Date.Value - DateTimeOffset.Now;
                    return Math.Max(1, (int)delta.TotalSeconds);
                }
            }
        }
        catch { }

        // Default fallback
        return 5;
    }

    /// <summary>
    /// Checks if text starts with any of the specified prefixes (case-insensitive).
    /// </summary>
    private static bool StartsWithAny(string text, IEnumerable<string> prefixes)
    {
        if (string.IsNullOrEmpty(text)) return false;

        foreach (var p in prefixes)
        {
            if (string.IsNullOrEmpty(p)) continue;
            if (text.StartsWith(p, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    /// <summary>
    /// Picks a random prefix from the configured list.
    /// </summary>
    private static string PickRandomPrefix(List<string> prefixes)
    {
        if (prefixes == null || prefixes.Count == 0) return "CYKJ";

        int idx = _rng.Next(prefixes.Count);
        return prefixes[idx];
    }

    /// <summary>
    /// Delays execution based on configuration (random delay within min/max range).
    /// </summary>
    private static Task DelayAsync(Config.RunConfig.DelayConfig? delay)
    {
        if (delay is null || !delay.Enabled)
            return Task.CompletedTask;

        int min = Math.Max(0, delay.MinSeconds);
        int max = Math.Max(min, delay.MaxSeconds);
        int secs = (min == max) ? min : _rng.Next(min, max + 1);

        return Task.Delay(TimeSpan.FromSeconds(secs));
    }
}

 // ============== Configuration Models ==============

public partial class Config
{
    public List<AccountConfig> Accounts { get; set; } = new();
    public List<string> Prefixes { get; set; } = new() { "CYKJ" };
    public Config.AssetsConfig? Assets { get; set; }
    public Config.NotificationConfig? Notification { get; set; }
    public Config.RunConfig? Run { get; set; }
    public Config.FeaturesConfig? Features { get; set; }

    public partial class AccountConfig
    {
        public string ClientId { get; set; } = "";
        public string ClientSecret { get; set; } = "";
        public string RefreshToken { get; set; } = "";
    }

    public partial class AssetsConfig
    {
        public AssetsConfig.ExcelAssets? Excel { get; set; }

        public partial class ExcelAssets
        {
            public string? MinimalWorkbookBase64 { get; set; }
        }
    }

    public partial class NotificationConfig
    {
        public NotificationConfig.EmailConfig? Email { get; set; }

        public partial class EmailConfig
        {
            public string? ToAddress { get; set; }
        }
    }

    public partial class RunConfig
    {
        public int Rounds { get; set; } = 1;
        public RunConfig.DelayConfig? ApiDelay { get; set; }
        public RunConfig.DelayConfig? RoundsDelay { get; set; }
        public RunConfig.DelayConfig? AccountDelay { get; set; }

        public partial class DelayConfig
        {
            public bool Enabled { get; set; }
            public int MinSeconds { get; set; }
            public int MaxSeconds { get; set; }
        }
    }

    public partial class FeaturesConfig
    {
        public FeaturesConfig.ReadFeatures? Read { get; set; }
        public FeaturesConfig.WriteFeatures? Write { get; set; }

        public partial class ReadFeatures
        {
            public int TaskMin{ get; set; } = 8;
            public bool UseExtendedApis { get; set; } = true;
        }

        public partial class WriteFeatures
        {
            public int TaskMin{ get; set; } = 6;
            public bool UploadRandomFile { get; set; } = true;
            public bool Excel { get; set; } = true;
            public bool Todo { get; set; } = true;
            public bool CalendarEvent { get; set; } = true;
            public bool Contacts { get; set; } = true;
            public bool MailDraft { get; set; } = true;
            public bool MailFolder { get; set; } = true;
            public bool MailRule { get; set; } = true;
            public bool OneNotePage { get; set; } = true;
            public bool DriveFolderWithShareLink { get; set; } = true;
            public bool UserOpenExtension { get; set; } = true;
            public bool GroupJoin { get; set; } = true;            
            public bool MailForwardReply { get; set; } = true;
            public bool FileCopyMove { get; set; } = true;
            public bool FileVersionManagement { get; set; } = true;
            public bool CalendarEventResponse { get; set; } = true;
            public bool TaskCompletion { get; set; } = true;
            public bool SharePointListItems { get; set; } = true;
            public bool UpdateUserProfile { get; set; } = true;
            public bool UpdatePresence { get; set; } = true;
        }
    }
}

public partial class TokenResponse
{
    [JsonPropertyName("access_token")] public string? AccessToken { get; set; }
    [JsonPropertyName("refresh_token")] public string? RefreshToken { get; set; }
    [JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
    [JsonPropertyName("token_type")] public string? TokenType { get; set; }
}


/// <summary>
/// Response model for GitHub repository public key.
/// </summary>
public record PublicKeyResp(string key_id, string key);

/// <summary>
/// Request model for GitHub secret upsert operation.
/// </summary>
public record UpsertReq(string encrypted_value, string key_id);

// ============== JSON Source Generator Context ==============

[JsonSourceGenerationOptions(
    PropertyNameCaseInsensitive = true,
    WriteIndented = false
)]
[JsonSerializable(typeof(UpsertReq))]
[JsonSerializable(typeof(PublicKeyResp))]
[JsonSerializable(typeof(TokenResponse))]
[JsonSerializable(typeof(Config))]
[JsonSerializable(typeof(List<Config.AccountConfig>))]
[JsonSerializable(typeof(Config.AccountConfig))]
[JsonSerializable(typeof(Config.AssetsConfig))]
[JsonSerializable(typeof(Config.AssetsConfig.ExcelAssets))]
[JsonSerializable(typeof(Config.NotificationConfig))]
[JsonSerializable(typeof(Config.NotificationConfig.EmailConfig))]
[JsonSerializable(typeof(Config.RunConfig))]
[JsonSerializable(typeof(Config.RunConfig.DelayConfig))]
[JsonSerializable(typeof(Config.FeaturesConfig))]
[JsonSerializable(typeof(Config.FeaturesConfig.ReadFeatures))]
[JsonSerializable(typeof(Config.FeaturesConfig.WriteFeatures))]
internal partial class ConfigContext : JsonSerializerContext
{
}

