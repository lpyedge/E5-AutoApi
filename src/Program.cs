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
using System.Threading.Tasks;
using System.Runtime.CompilerServices;

public class Program
{
    private static readonly HttpClient _http = new HttpClient();
    private static readonly Random _rng = new Random();
    private static Config? _cfg;
    private const string ConfigPath = "Config.json";
    private static bool loadedFromEnv = false;

    public static async Task Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        _cfg = await LoadConfigAsync();
        if (_cfg == null)
        {
            Console.WriteLine($" [ERROR] 無法載入設定，請檢查 {ConfigPath}。");
            return;
        }
        // 嘗試從環境變量覆蓋賬號
        OverrideAccountsFromEnvironment(_cfg);

        string mode = (args.Length > 0 ? args[0] : "both").Trim().ToLowerInvariant();
        bool refreshToken = mode is "refresh";
        bool runRead = mode is "read" or "both";
        bool runWrite = mode is "write" or "both";

        for (int i = 0; i < _cfg.Accounts.Count; i++)
        {
            var acct = _cfg.Accounts[i];
            Console.WriteLine($"========== Account #{i + 1} ==========");

            var token = await GetAccessTokenAsync(acct);
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.WriteLine(" [ERROR] 無法取得 access_token，略過此帳號。");
                await DelayAsync(_cfg.Run?.AccountDelay);
                continue;
            }

            if (runWrite && !string.IsNullOrWhiteSpace(_cfg.Notification?.Email?.ToAddress))
            {
                _ = SendEmailAsync(token, _cfg.Notification.Email.ToAddress!,
                    "Graph 自動化任務開始",
                    $"帳號 {i + 1} 寫入任務開始於 {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}");
            }
            if (refreshToken)
            {
                bool ok = await RefreshTokensAsync(_cfg, loadedFromEnv);
                if (!ok)
                {
                    Console.WriteLine(" [FATAL] 刷新 token 過程中發生致命錯誤，請檢查日誌。");
                    return; // 整個程序退出
                }
                // 刷新後不進行其他操作
                break;
            }
            else
            {
                int rounds = Math.Max(1, _cfg.Run?.Rounds ?? 1);
                for (int r = 1; r <= rounds; r++)
                {
                    Console.WriteLine($"-- Round {r}/{rounds} --");

                    // 每輪隨機選一個前綴
                    string chosenPrefix = PickRandomPrefix(_cfg.Prefixes);
                    Console.WriteLine($" [INFO] 本輪前綴：{chosenPrefix}");               

                    if (runRead) await RunReadModeAsync(token);

                    if (runWrite) await RunWriteModeAsync(token, chosenPrefix);

                    // 總清理：針對 Prefixes 集合中所有前綴清理殘留
                    await CleanupAllPrefixesAsync(token, _cfg.Prefixes);

                    if (r < rounds) await DelayAsync(_cfg.Run?.RoundsDelay);
                }
            }

            if (i < _cfg.Accounts.Count - 1) await DelayAsync(_cfg.Run?.AccountDelay);
        }

        Console.WriteLine("All done.");
    }

    // ============== Config ==============
    static string GetSourceFilePath(string fileName,
        [CallerFilePath] string sourceFile = "")
    {
        return Path.Combine(
            Path.GetDirectoryName(sourceFile) ?? "",
            fileName
        );
    }

    private static async Task<Config?> LoadConfigAsync()
    {
        var configPath = GetSourceFilePath(ConfigPath);
        if (!File.Exists(configPath))
        {
            Console.WriteLine($" [ERROR] 找不到設定檔：{configPath}");
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
            Console.WriteLine($" [ERROR] 解析設定檔失敗：{ex.Message}");
            return null;
        }
    }

    private static void OverrideAccountsFromEnvironment(Config cfg)
    {
        try
        {
            var json = Environment.GetEnvironmentVariable("ACCOUNTS_JSON");
            if (string.IsNullOrWhiteSpace(json))
                return; // 無環境變數，保持原配置

            var list = JsonSerializer.Deserialize<List<Config.AccountConfig>>(json, ConfigContext.Default.Options);

            if (list != null && list.Count > 0 &&
                list.All(a => !string.IsNullOrWhiteSpace(a.ClientId)
                        && !string.IsNullOrWhiteSpace(a.ClientSecret)
                        && !string.IsNullOrWhiteSpace(a.RefreshToken)))
            {
                cfg.Accounts = list; // 覆蓋配置文件中的 Accounts
                loadedFromEnv = true;
                Console.WriteLine($" [INFO] 已從環境變數 ACCOUNTS_JSON 載入 {list.Count} 個帳號。");
            }
            else
            {
                Console.WriteLine(" [WARN] ACCOUNTS_JSON 內容為空或結構不完整，忽略覆蓋。");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [WARN] 解析 ACCOUNTS_JSON 失敗：{ex.Message}，忽略覆蓋。");
        }
    }
  

    private record PublicKeyResp(string key_id, string key);
    private record UpsertReq(string encrypted_value, string key_id);

    private static async System.Threading.Tasks.Task UpsertAsync(string name, string plaintext)
    {
        var owner_repo = Environment.GetEnvironmentVariable("GH_REPO");
        var token = Environment.GetEnvironmentVariable("GH_TOKEN");

        using var http = new HttpClient();
        http.DefaultRequestHeaders.UserAgent.ParseAdd("dotnet-secrets-client");
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        http.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");

        // 1) 取得仓库公钥 [web:154]
        var pkUrl = $"https://api.github.com/repos/{owner_repo}/actions/secrets/public-key";
        var pkJson = await http.GetStringAsync(pkUrl);
        var pk = JsonSerializer.Deserialize<PublicKeyResp>(pkJson)!; // key(base64) + key_id [web:154]

        // 2) sealed box 加密，输出 base64 [web:155][web:159]
        var pubKeyBytes = Convert.FromBase64String(pk.key);
        var cipher = Sodium.SealedPublicKeyBox.Create(Encoding.UTF8.GetBytes(plaintext), pubKeyBytes); // [web:159]
        var encB64 = Convert.ToBase64String(cipher); // GitHub 要求 base64 封装 [web:155]

        // 3) PUT 更新 Secret [web:154]
        var putUrl = $"https://api.github.com/repos/{owner_repo}/actions/secrets/{name}";
        var body = JsonSerializer.Serialize(new UpsertReq(encB64, pk.key_id));
        

        var resp = await http.PutAsync(putUrl, new StringContent(body, Encoding.UTF8, "application/json"));
        resp.EnsureSuccessStatusCode(); // 201/204 表示成功 [web:154]
    }
    // ============== Endpoints ==============

    private static class EP
    {
        public const string TokenUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
        public const string RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient";
        public const string V1 = "https://graph.microsoft.com/v1.0";

        // OneDrive
        public static string SearchDriveItems(string q) => $"{V1}/me/drive/root/search(q='{Uri.EscapeDataString(q)}')";
        public static string DeleteDriveItem(string id) => $"{V1}/me/drive/items/{id}";
        public static string UploadRootContent(string fileName) => $"{V1}/me/drive/root:/{Uri.EscapeDataString(fileName)}:/content";
        public static string CreateFolderUnderRoot => $"{V1}/me/drive/root/children";
        public static string DriveItemChildren(string id) => $"{V1}/me/drive/items/{id}/children";
        public static string DriveItemCreateLink(string id) => $"{V1}/me/drive/items/{id}/createLink";
        public static string DriveItemPermissions(string id, string permId) => $"{V1}/me/drive/items/{id}/permissions/{permId}";
        public static string UploadUnderItem(string parentId, string name) => $"{V1}/me/drive/items/{parentId}:/{Uri.EscapeDataString(name)}:/content";

        // Excel
        public static string ExcelWorksheets(string itemId) => $"{V1}/me/drive/items/{itemId}/workbook/worksheets";
        public static string ExcelTablesAdd(string itemId, string sheetName) => $"{V1}/me/drive/items/{itemId}/workbook/worksheets/{Uri.EscapeDataString(sheetName)}/tables/add";
        public static string ExcelTableRowsAdd(string itemId, string tableId) => $"{V1}/me/drive/items/{itemId}/workbook/tables/{Uri.EscapeDataString(tableId)}/rows/add";

        // To Do
        public static string TodoLists => $"{V1}/me/todo/lists";
        public static string TodoListById(string listId) => $"{V1}/me/todo/lists/{Uri.EscapeDataString(listId)}";
        public static string TodoTasks(string listId) => $"{V1}/me/todo/lists/{Uri.EscapeDataString(listId)}/tasks";

        // Outlook mail
        public static string SendMail => $"{V1}/me/sendMail";
        public static string CreateMessage => $"{V1}/me/messages";
        public static string MessageById(string id) => $"{V1}/me/messages/{id}";
        public static string MailFolders => $"{V1}/me/mailFolders";
        public static string MailFolderById(string id) => $"{V1}/me/mailFolders/{id}";
        public static string InboxRules => $"{V1}/me/mailFolders/Inbox/messageRules";
        public static string InboxRuleById(string id) => $"{V1}/me/mailFolders/Inbox/messageRules/{id}";

        // Contacts
        public static string Contacts => $"{V1}/me/contacts";
        public static string ContactById(string id) => $"{V1}/me/contacts/{id}";

        // Calendar
        public static string Events => $"{V1}/me/events";
        public static string EventById(string id) => $"{V1}/me/events/{id}";

        // OneNote
        public static string OneNotePages => $"{V1}/me/onenote/pages";
        public static string OneNotePageById(string id) => $"{V1}/me/onenote/pages/{id}";

        // User open extensions
        public static string UserExtensions => $"{V1}/me/extensions";
        public static string UserExtensionByName(string name) => $"{V1}/me/extensions/{Uri.EscapeDataString(name)}";

        // Groups
        public static string MemberOf => $"{V1}/me/memberOf";
        public static string Groups => $"{V1}/groups";
        public static string GroupById(string groupId) => $"{V1}/groups/{Uri.EscapeDataString(groupId)}";
        public static string GroupMembers(string groupId) => $"{V1}/groups/{Uri.EscapeDataString(groupId)}/members";
        public static string RemoveMemberRef(string groupId, string userId) => $"{V1}/groups/{Uri.EscapeDataString(groupId)}/members/{Uri.EscapeDataString(userId)}/$ref";

        // Read endpoints
        public static IEnumerable<string> ReadEndpoints(DateTimeOffset now, bool extended)
        {
            var start = now.ToUniversalTime().ToString("o");
            var end = now.AddDays(1).ToUniversalTime().ToString("o");

            var eps = new List<string>
            {
                $"{V1}/me",
                $"{V1}/me/profile",
                $"{V1}/me/presence",
                $"{V1}/me/people",
                $"{V1}/me/memberOf",
                $"{V1}/me/transitiveMemberOf",
                $"{V1}/me/messages?$top=5",
                $"{V1}/me/mailFolders",
                $"{V1}/me/mailFolders/Inbox/messages/delta",
                $"{V1}/me/outlook/masterCategories",
                $"{V1}/me/contacts",
                $"{V1}/me/contactFolders",
                $"{V1}/me/drive",
                $"{V1}/me/drive/quota",
                $"{V1}/me/drive/root",
                $"{V1}/me/drive/root/children?$top=10",
                $"{V1}/me/drive/recent",
                $"{V1}/me/drive/sharedWithMe",
                $"{V1}/me/drive/special",
                $"{V1}/me/calendar",
                $"{V1}/me/calendars",
                $"{V1}/me/events?$top=5",
                $"{V1}/me/calendar/calendarView?startDateTime={Uri.EscapeDataString(start)}&endDateTime={Uri.EscapeDataString(end)}",
                $"{V1}/me/onenote/notebooks",
                $"{V1}/me/onenote/sections",
                $"{V1}/me/onenote/pages?$top=5",
                $"{V1}/me/todo/lists",
                $"{V1}/me/insights/used",
                $"{V1}/me/insights/trending",
                $"{V1}/sites?search=*",
                $"{V1}/me/extensions"
            };

            if (extended)
            {
                eps.Add($"{V1}/me/drive/search(q='CYKJ')");
                eps.Add($"{V1}/me/photos/48x48/$value");
                eps.Add($"{V1}/me/joinedTeams"); // 讀取已加入的 Teams（若無權限會自動忽略錯誤）
            }

            return eps;
        }
    }

    // ============== OAuth ==============
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
                    new KeyValuePair<string,string>("client_id", a.ClientId),
                    new KeyValuePair<string,string>("client_secret", a.ClientSecret ?? ""),
                    new KeyValuePair<string,string>("grant_type", "refresh_token"),
                    new KeyValuePair<string,string>("refresh_token", a.RefreshToken),
                    // scope 可省略，若需要可加上 .default
                    // new KeyValuePair<string,string>("scope", "https://graph.microsoft.com/.default"),
                });

                using var resp = await _http.PostAsync($"https://login.microsoftonline.com/common/oauth2/v2.0/token", body);
                var txt = await resp.Content.ReadAsStringAsync();

                if (!resp.IsSuccessStatusCode)
                {
                    Console.WriteLine($" ***ERROR*** 刷新帳號#{i+1} 失敗：{txt}");
                    // 客戶端機密過期/無效或 refresh token 失效 → 強制失敗
                    if (txt.Contains("AADSTS7000222") || txt.Contains("AADSTS7000215") || txt.Contains("invalid_grant") || txt.Contains("9002313"))
                        anyFatal = true; // 需要人工處理
                    continue;
                }

                // 使用源生成 Context 解析
                var token = JsonSerializer.Deserialize<TokenResponse>(txt, ConfigContext.Default.TokenResponse);
                if (token == null || string.IsNullOrWhiteSpace(token.RefreshToken))
                {
                    Console.WriteLine($" ***WARN*** 帳號#{i+1} 未取得新的 refresh_token。");
                    continue;
                }

                // 重要：用新 refresh_token 取代舊值（滾動刷新）
                a.RefreshToken = token.RefreshToken;
                Console.WriteLine($" [OK] 帳號#{i+1} 已更新 refresh_token（長度 {a.RefreshToken.Length}）。");
            }
            catch (Exception ex)
            {
                Console.WriteLine($" ***ERROR*** 帳號#{i+1} 刷新例外：{ex.Message}");
                anyFatal = true;
            }
        }

        // 寫回來源
        if (loadedFromEnv)
        {
            var oneLine = JsonSerializer.Serialize(cfg.Accounts, ConfigContext.Default.ListAccountConfig);
            await UpsertAsync("ACCOUNTS_JSON", oneLine);
            Console.WriteLine($" [INFO] 已写入新的 ACCOUNTS_JSON");
        }
        else
        {
            var configPath = GetSourceFilePath("Config.json");
            // 更新整個配置（保證 Accounts 寫回）
            await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(cfg, ConfigContext.Default.Config), Encoding.UTF8);
            Console.WriteLine($" [INFO] 已寫回 Config.json：{configPath}");
        }

        if (anyFatal)
        {
            Console.WriteLine(" ***FATAL*** 偵測到 client secret 過期/無效或 refresh token 失效，請更新機密或重新授權。");
            Environment.Exit(1); // 讓 GitHub Actions 失敗，提醒人工處理
        }

        return !anyFatal;
    }
    private static async Task<string> GetAccessTokenAsync(Config.AccountConfig a)
    {
        try
        {
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string,string>("grant_type","refresh_token"),
                new KeyValuePair<string,string>("refresh_token", a.RefreshToken),
                new KeyValuePair<string,string>("client_id", a.ClientId),
                new KeyValuePair<string,string>("client_secret", a.ClientSecret),
                new KeyValuePair<string,string>("redirect_uri", EP.RedirectUri)
            });
            var resp = await _http.PostAsync(EP.TokenUrl, content);
            var body = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode)
            {
                Console.WriteLine($" [ERROR] 取得 token 失敗：{resp.StatusCode} {body}");
                return string.Empty;
            }
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("access_token", out var t) ? (t.GetString() ?? "") : "";
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [ERROR] GetAccessToken 例外：{ex.Message}");
            return string.Empty;
        }
    }

    // ============== Read ==============

    private static async Task RunReadModeAsync(string token)
    {
        Console.WriteLine(" [INFO] Read 模式開始。");
        var endpoints = EP.ReadEndpoints(DateTimeOffset.Now, _cfg?.Features?.Read?.UseExtendedApis ?? true).ToList();
        Shuffle(endpoints);

        int ok = 0, fail = 0;
        foreach (var url in endpoints)
        {
            if (await TryGetAsync(url, token)) ok++; else fail++;
            await DelayAsync(_cfg?.Run?.ApiDelay);
        }
        Console.WriteLine($" [INFO] Read 模式完成，成功 {ok}，失敗 {fail}。");
    }

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

                if ((int)resp.StatusCode == 429)
                {
                    var retry = GetRetryAfterSeconds(resp);
                    Console.WriteLine($" [WARN] 429 Too Many Requests，等待 {retry}s 後重試。");
                    await Task.Delay(TimeSpan.FromSeconds(retry));
                    continue;
                }

                if ((int)resp.StatusCode >= 400 && (int)resp.StatusCode < 500 && resp.StatusCode != HttpStatusCode.RequestTimeout)
                {
                    Console.WriteLine($" [FAIL] GET {url} => {(int)resp.StatusCode} {resp.ReasonPhrase}");
                    return false;
                }

                Console.WriteLine($" [WARN] GET {url} => {(int)resp.StatusCode}，嘗試重試。");
            }
            catch (Exception ex)
            {
                Console.WriteLine($" [WARN] GET {url} 例外：{ex.Message}，嘗試重試。");
            }
            await DelayAsync(_cfg?.Run?.ApiDelay);
        }
        return false;
    }

    // ============== Write ==============
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
        req.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

        using var resp = await _http.SendAsync(req);
        if (!resp.IsSuccessStatusCode)
        {
            var text = await resp.Content.ReadAsStringAsync();
            Console.WriteLine($" [WARN] 發送郵件失敗：{resp.StatusCode} {text}");
        }
    }
    private static async Task RunWriteModeAsync(string token, string prefix)
    {
        Console.WriteLine(" [INFO] Write 模式開始。");

        var wf = _cfg?.Features?.Write ?? new Config.FeaturesConfig.WriteFeatures();

        var ops = new List<Func<string, string, Task>>
        {
            wf.UploadRandomFile ? UploadRandomFileAsync : null,
            wf.Excel ? ExcelWorkbookAndTableAsync : null,
            wf.Todo ? TodoListAndTaskAsync : null,
            wf.CalendarEvent ? CalendarEventRoundtripAsync : null,
            wf.Contacts ? ContactRoundtripAsync : null,
            wf.MailDraft ? MailDraftRoundtripAsync : null,
            wf.MailFolder ? MailFolderRoundtripAsync : null,
            wf.MailRule ? MailRuleRoundtripAsync : null,
            wf.OneNotePage ? OneNotePageRoundtripAsync : null,
            wf.DriveFolderWithShareLink ? DriveFolderFileShareRoundtripAsync : null,
            wf.UserOpenExtension ? UserOpenExtensionRoundtripAsync : null,
            wf.GroupJoin ? GroupJoinRoundtripAsync : null
        }
        .Where(f => f != null)
        .Cast<Func<string, string, Task>>()
        .ToList();

        Shuffle(ops);

        // 為降低相互影響，單輪最多執行 4 個寫操作（可依需要調整）
        foreach (var op in ops.Take(Math.Min(4, ops.Count)))
        {
            try { await op(token, prefix); }
            catch (Exception ex) { Console.WriteLine($" [ERROR] 寫入操作例外：{ex.Message}"); }
            await DelayAsync(_cfg?.Run?.ApiDelay);
        }

        Console.WriteLine(" [INFO] Write 模式完成。");
    }

    // OneDrive: 上傳小檔後立即刪除（自清理）
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
            Console.WriteLine($" [FAIL] 上傳 {fileName} 失敗：{resp.StatusCode}");
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
        Console.WriteLine($" [OK] 上傳並刪除 {fileName}");
    }

    // Excel：從配置載入樣板 -> 上傳 -> 建表 -> 寫入 -> 刪除工作簿
    private static async Task ExcelWorkbookAndTableAsync(string token, string prefix)
    {
        var base64 = _cfg?.Assets?.Excel?.MinimalWorkbookBase64;
        if (string.IsNullOrWhiteSpace(base64))
        {
            Console.WriteLine(" [INFO] 未提供 Excel 樣板，略過 Excel 流程。");
            return;
        }
        byte[] bytes;
        try { bytes = Convert.FromBase64String(base64); }
        catch { Console.WriteLine(" [WARN] Excel 樣板 Base64 無效，略過。"); return; }

        var name = $"{prefix}_{DateTimeOffset.Now:yyyyMMdd_HHmmss}_{_rng.Next(1000, 9999)}.xlsx";

        // 上傳工作簿
        string? itemId = null;
        using (var req = new HttpRequestMessage(HttpMethod.Put, EP.UploadRootContent(name)))
        {
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Content = new ByteArrayContent(bytes);
            req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) { Console.WriteLine($" [FAIL] 上傳工作簿失敗：{resp.StatusCode} {text}"); return; }
            using var doc = JsonDocument.Parse(text);
            itemId = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;
            if (string.IsNullOrWhiteSpace(itemId)) { Console.WriteLine(" [FAIL] 工作簿回應無 id。"); return; }
        }

        try
        {
            await DelayAsync(_cfg?.Run?.ApiDelay);

            // 建立工作表
            var wsName = "SheetCYKJ";
            var wsBody = JsonSerializer.Serialize(new { name = wsName });
            using (var wsReq = new HttpRequestMessage(HttpMethod.Post, EP.ExcelWorksheets(itemId!)))
            {
                wsReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                wsReq.Content = new StringContent(wsBody, Encoding.UTF8, "application/json");
                using var wsResp = await _http.SendAsync(wsReq);
                if (!wsResp.IsSuccessStatusCode) { Console.WriteLine($" [FAIL] 建立工作表失敗：{wsResp.StatusCode}"); return; }
            }

            await DelayAsync(_cfg?.Run?.ApiDelay);

            // 建立表格
            var tblBody = JsonSerializer.Serialize(new { address = "SheetCYKJ!A1:B1", hasHeaders = true });
            string? tableId = null;
            using (var tReq = new HttpRequestMessage(HttpMethod.Post, EP.ExcelTablesAdd(itemId!, wsName)))
            {
                tReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                tReq.Content = new StringContent(tblBody, Encoding.UTF8, "application/json");
                using var tResp = await _http.SendAsync(tReq);
                var tText = await tResp.Content.ReadAsStringAsync();
                if (!tResp.IsSuccessStatusCode) { Console.WriteLine($" [FAIL] 建立表格失敗：{tResp.StatusCode} {tText}"); return; }
                using var tDoc = JsonDocument.Parse(tText);
                tableId = tDoc.RootElement.TryGetProperty("id", out var tip) ? tip.GetString() : null;
                if (string.IsNullOrWhiteSpace(tableId)) { Console.WriteLine(" [FAIL] 表格回應無 id。"); return; }
            }

            await DelayAsync(_cfg?.Run?.ApiDelay);

            // 寫入資料列
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
            rReq.Content = new StringContent(JsonSerializer.Serialize(rowsPayload), Encoding.UTF8, "application/json");
            using var rResp = await _http.SendAsync(rReq);
            Console.WriteLine(rResp.IsSuccessStatusCode ? " [OK] Excel 寫入完成。" : $" [FAIL] Excel 寫入失敗：{rResp.StatusCode}");
        }
        finally
        {
            // 刪除工作簿
            using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.DeleteDriveItem(itemId!));
            dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            await _http.SendAsync(dReq);
        }
    }

    private static async Task TodoListAndTaskAsync(string token, string prefix)
    {
        string? listId = null;
        try
        {
            var listName = $"{prefix}_List_{_rng.Next(10000, 99999)}";
            using (var lReq = new HttpRequestMessage(HttpMethod.Post, EP.TodoLists))
            {
                lReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                lReq.Content = new StringContent(JsonSerializer.Serialize(new { displayName = listName }), Encoding.UTF8, "application/json");
                using var lResp = await _http.SendAsync(lReq);
                var lText = await lResp.Content.ReadAsStringAsync();
                if (!lResp.IsSuccessStatusCode) { Console.WriteLine($" [FAIL] 建立 ToDo 清單失敗：{lResp.StatusCode} {lText}"); return; }
                using var lDoc = JsonDocument.Parse(lText);
                listId = lDoc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;
                if (string.IsNullOrWhiteSpace(listId)) { Console.WriteLine(" [FAIL] ToDo 清單回應無 id"); return; }
            }

            var taskTitle = $"{prefix}_Task_{_rng.Next(10000, 99999)}";
            using (var tReq = new HttpRequestMessage(HttpMethod.Post, EP.TodoTasks(listId!)))
            {
                tReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                tReq.Content = new StringContent(JsonSerializer.Serialize(new { title = taskTitle }), Encoding.UTF8, "application/json");
                using var tResp = await _http.SendAsync(tReq);
                if (!tResp.IsSuccessStatusCode) Console.WriteLine($" [WARN] 建立任務失敗：{tResp.StatusCode}");
            }
            Console.WriteLine(" [OK] 建立 ToDo 清單完成。");
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
            req.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) { Console.WriteLine($" [FAIL] 建立事件失敗：{resp.StatusCode} {text}"); return; }
            using var doc = JsonDocument.Parse(text);
            eventId = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;
            Console.WriteLine(string.IsNullOrWhiteSpace(eventId) ? " [FAIL] 事件回應無 id" : " [OK] 建立事件完成。");
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

    private static async Task ContactRoundtripAsync(string token, string prefix)
    {
        string? id = null;
        try
        {
            var displayName = $"{prefix}_Contact_{_rng.Next(10000, 99999)}";
            var body = new { displayName, givenName = prefix, emailAddresses = new[] { new { address = "foo@example.com", name = "Foo" } } };
            using var req = new HttpRequestMessage(HttpMethod.Post, EP.Contacts);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) { Console.WriteLine($" [FAIL] 建立聯絡人失敗：{resp.StatusCode} {text}"); return; }
            using var doc = JsonDocument.Parse(text);
            id = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;
            Console.WriteLine(string.IsNullOrWhiteSpace(id) ? " [FAIL] 聯絡人回應無 id" : " [OK] 建立聯絡人完成。");
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

    private static async Task MailDraftRoundtripAsync(string token, string prefix)
    {
        string? id = null;
        try
        {
            var subject = $"{prefix}_Draft_{_rng.Next(10000, 99999)}";
            var body = new { subject, body = new { contentType = "Text", content = "Draft content" }, toRecipients = new object[] { } };
            using var req = new HttpRequestMessage(HttpMethod.Post, EP.CreateMessage);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) { Console.WriteLine($" [FAIL] 建立草稿失敗：{resp.StatusCode} {text}"); return; }
            using var doc = JsonDocument.Parse(text);
            id = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;
            Console.WriteLine(string.IsNullOrWhiteSpace(id) ? " [FAIL] 草稿回應無 id" : " [OK] 建立草稿完成。");
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

    private static async Task MailFolderRoundtripAsync(string token, string prefix)
    {
        string? id = null;
        try
        {
            var name = $"{prefix}_Folder_{_rng.Next(10000, 99999)}";
            var body = new { displayName = name };
            using var req = new HttpRequestMessage(HttpMethod.Post, EP.MailFolders);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) { Console.WriteLine($" [FAIL] 建立郵件資料夾失敗：{resp.StatusCode} {text}"); return; }
            using var doc = JsonDocument.Parse(text);
            id = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;
            Console.WriteLine(string.IsNullOrWhiteSpace(id) ? " [FAIL] 資料夾回應無 id" : " [OK] 建立郵件資料夾完成。");
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
                conditions = new { messageContainsWords = new[] { "graph" } },
                actions = new { stopProcessingRules = true }
            };
            using var req = new HttpRequestMessage(HttpMethod.Post, EP.InboxRules);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) { Console.WriteLine($" [WARN] 建立郵件規則失敗：{resp.StatusCode} {text}"); return; }
            using var doc = JsonDocument.Parse(text);
            id = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;
            if (!string.IsNullOrWhiteSpace(id)) Console.WriteLine(" [OK] 建立郵件規則完成。");
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

    private static async Task OneNotePageRoundtripAsync(string token, string prefix)
    {
        string? id = null;
        try
        {
            var title = $"{prefix}_OneNote_{_rng.Next(10000, 99999)}";
            var html = $"<html><head><title>{System.Net.WebUtility.HtmlEncode(title)}</title></head><body><p>Created at {DateTimeOffset.Now:o}</p></body></html>";
            using var req = new HttpRequestMessage(HttpMethod.Post, EP.OneNotePages);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Content = new StringContent(html, Encoding.UTF8, "application/xhtml+xml");
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) { Console.WriteLine($" [WARN] 建立 OneNote 頁面失敗：{resp.StatusCode} {text}"); return; }
            using var doc = JsonDocument.Parse(text);
            id = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;
            if (!string.IsNullOrWhiteSpace(id)) Console.WriteLine(" [OK] 建立 OneNote 頁面完成。");
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

    private static async Task DriveFolderFileShareRoundtripAsync(string token, string prefix)
    {
        string? folderId = null;
        try
        {
            // 建立資料夾
            var folderName = $"{prefix}_Dir_{_rng.Next(10000, 99999)}";
            var body = new Dictionary<string, object>
            {
                ["name"] = folderName,
                ["folder"] = new Dictionary<string, object>(),
                ["@microsoft.graph.conflictBehavior"] = "rename"
            };
            using (var req = new HttpRequestMessage(HttpMethod.Post, EP.CreateFolderUnderRoot))
            {
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                req.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
                using var resp = await _http.SendAsync(req);
                var text = await resp.Content.ReadAsStringAsync();
                if (!resp.IsSuccessStatusCode) { Console.WriteLine($" [WARN] 建立資料夾失敗：{resp.StatusCode} {text}"); return; }
                using var doc = JsonDocument.Parse(text);
                folderId = doc.RootElement.TryGetProperty("id", out var idp) ? idp.GetString() : null;
                if (string.IsNullOrWhiteSpace(folderId)) { Console.WriteLine(" [FAIL] 資料夾回應無 id"); return; }
            }

            await DelayAsync(_cfg?.Run?.ApiDelay);

            // 上傳檔案到資料夾
            var fileName = $"{prefix}_Inner_{_rng.Next(10000, 99999)}.txt";
            using (var uReq = new HttpRequestMessage(HttpMethod.Put, EP.UploadUnderItem(folderId!, fileName)))
            {
                uReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                var bytes = Encoding.UTF8.GetBytes("hello");
                uReq.Content = new ByteArrayContent(bytes);
                uReq.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                using var uResp = await _http.SendAsync(uReq);
                if (!uResp.IsSuccessStatusCode) { Console.WriteLine($" [WARN] 上傳子檔案失敗：{uResp.StatusCode}"); }
            }

            await DelayAsync(_cfg?.Run?.ApiDelay);

            // 建立分享連結，然後刪除該權限
            string? permId = null;
            using (var sReq = new HttpRequestMessage(HttpMethod.Post, EP.DriveItemCreateLink(folderId!)))
            {
                sReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                sReq.Content = new StringContent(JsonSerializer.Serialize(new { type = "view", scope = "anonymous" }), Encoding.UTF8, "application/json");
                using var sResp = await _http.SendAsync(sReq);
                var sText = await sResp.Content.ReadAsStringAsync();
                if (sResp.IsSuccessStatusCode)
                {
                    using var sDoc = JsonDocument.Parse(sText);
                    if (sDoc.RootElement.TryGetProperty("id", out var pid)) permId = pid.GetString();
                }
                else
                {
                    Console.WriteLine($" [WARN] 建立分享連結失敗：{sResp.StatusCode} {sText}");
                }
            }

            if (!string.IsNullOrWhiteSpace(permId))
            {
                using var pDel = new HttpRequestMessage(HttpMethod.Delete, EP.DriveItemPermissions(folderId!, permId!));
                pDel.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(pDel);
            }

            Console.WriteLine(" [OK] Drive 資料夾與分享連結完成。");
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
                cReq.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                using var cResp = await _http.SendAsync(cReq);
                if (!cResp.IsSuccessStatusCode) { Console.WriteLine($" [WARN] 建立 user 擴展失敗：{cResp.StatusCode}"); return; }
            }

            // 讀取一下再刪除
            using (var gReq = new HttpRequestMessage(HttpMethod.Get, EP.UserExtensionByName(name)))
            {
                gReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                await _http.SendAsync(gReq);
            }

            Console.WriteLine(" [OK] User 擴展完成。");
        }
        finally
        {
            using var dReq = new HttpRequestMessage(HttpMethod.Delete, EP.UserExtensionByName(name));
            dReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            await _http.SendAsync(dReq);
        }
    }

    // ============== Groups Write (新增) ==============
    /// <summary>
    /// 群組寫入流程:先列出當前使用者所屬的公開 M365 群組,若有就試著建立一個測試 group 並加入自己再馬上刪除;
    /// 若無則僅做一次 memberOf 讀取記錄一下。
    /// 注意:建立 group 需要 Group.ReadWrite.All 以上權限,且使用者需具備相應 Entra 角色(如 Groups Administrator)。
    /// 由於許多租戶不允許一般使用者建立群組,此方法僅做嘗試,失敗時會記錄而不中斷流程。
    /// </summary>
    private static async Task GroupJoinRoundtripAsync(string token, string prefix)
    {
        // 由於大部分租戶禁止一般使用者建立 group,這裡改為只做「列出自己所屬群組」的寫入模擬
        // 並在清理階段實作退出所有帶前綴的群組。
        // 實際「建立群組並加入」需要系統管理員權限,在委派情境下不適用,故略過建立流程。
        Console.WriteLine(" [INFO] Group write 僅執行 memberOf 讀取(建立群組需要額外系統管理員權限)。");
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, EP.MemberOf);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (resp.IsSuccessStatusCode)
            {
                Console.WriteLine(" [OK] 已讀取 memberOf。");
            }
            else
            {
                Console.WriteLine($" [WARN] 讀取 memberOf 失敗:{resp.StatusCode} {text}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [WARN] Group write 例外:{ex.Message}");
        }
    }

    // ============== Cleanup (all prefixes) ==============

    private static async Task CleanupAllPrefixesAsync(string token, List<string> prefixes)
    {
        if (prefixes == null || prefixes.Count == 0) return;

        // OneDrive
        foreach (var p in prefixes)
            await CleanupDriveByPrefixAsync(token, p);

        // ToDo lists
        await CleanupTodoListsByPrefixesAsync(token, prefixes);

        // Calendar events (僅清理未來一小段時間內的自建事件以降低掃描成本)
        await CleanupCalendarByPrefixesAsync(token, prefixes);

        // Contacts
        await CleanupContactsByPrefixesAsync(token, prefixes);

        // Mail: drafts + folders + rules
        await CleanupMailDraftsByPrefixesAsync(token, prefixes);
        await CleanupMailFoldersByPrefixesAsync(token, prefixes);
        await CleanupMailRulesByPrefixesAsync(token, prefixes);

        // OneNote pages
        await CleanupOneNotePagesByPrefixesAsync(token, prefixes);

        // User open extensions
        await CleanupUserExtensionsByPrefixesAsync(token, prefixes);

        // Groups cleanup 退出所有 displayName 以 prefixes 開頭的群組
        await CleanupGroupMembershipByPrefixesAsync(token, prefixes);
    }

    private static async Task CleanupDriveByPrefixAsync(string token, string prefix)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, EP.SearchDriveItems(prefix));
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode) { Console.WriteLine($" [WARN] Drive 搜尋失敗：{resp.StatusCode} {text}"); return; }
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
        catch (Exception ex) { Console.WriteLine($" [WARN] 清理 Drive 例外：{ex.Message}"); }
    }

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
            Console.WriteLine($" [WARN] 清理 ToDo 清單例外：{ex.Message}");
        }
    }

    private static async Task CleanupCalendarByPrefixesAsync(string token, List<string> prefixes)
    {
        try
        {
            // 取部分事件用於清理（避免大範圍掃描）
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
            Console.WriteLine($" [WARN] 清理 Calendar 例外：{ex.Message}");
        }
    }

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

                // 處理分頁
                url = doc.RootElement.TryGetProperty("@odata.nextLink", out var link) ? link.GetString() : null;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [WARN] 清理 Contacts 例外：{ex.Message}");
        }
    }

    private static async Task CleanupMailDraftsByPrefixesAsync(string token, List<string> prefixes)
    {
        try
        {
            // 僅清理草稿，避免誤刪實際郵件
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
            Console.WriteLine($" [WARN] 清理 Mail Drafts 例外：{ex.Message}");
        }
    }

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
            Console.WriteLine($" [WARN] 清理 Mail Folders 例外：{ex.Message}");
        }
    }

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
            Console.WriteLine($" [WARN] 清理 Mail Rules 例外：{ex.Message}");
        }
    }

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
            Console.WriteLine($" [WARN] 清理 OneNote 頁面例外：{ex.Message}");
        }
    }

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
            Console.WriteLine($" [WARN] 清理 User Extensions 例外:{ex.Message}");
        }
    }

    // ============== Groups Cleanup ==============
    /// <summary>
    /// 清理所有 displayName 以 prefixes 開頭的群組成員身分:
    /// 1) GET /me/memberOf 取得使用者所屬群組
    /// 2) 對匹配前綴的群組,呼叫 DELETE /groups/{group-id}/members/{user-id}/$ref 退出
    /// 3) GET /me 取得使用者 id 用於構造刪除端點
    /// 注意:只能刪除一般分配成員的群組,動態成員資格群組不支援手動移除;個人 Microsoft 帳戶也不支援此 API。
    /// </summary>
    private static async Task CleanupGroupMembershipByPrefixesAsync(string token, List<string> prefixes)
    {
        try
        {
            // 1) 取得當前使用者 id
            string? userId = null;
            using (var meReq = new HttpRequestMessage(HttpMethod.Get, $"{EP.V1}/me?$select=id"))
            {
                meReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                using var meResp = await _http.SendAsync(meReq);
                var meText = await meResp.Content.ReadAsStringAsync();
                if (!meResp.IsSuccessStatusCode)
                {
                    Console.WriteLine($" [WARN] 無法取得使用者 id:{meResp.StatusCode} {meText}");
                    return;
                }
                using var meDoc = JsonDocument.Parse(meText);
                userId = meDoc.RootElement.TryGetProperty("id", out var uidp) ? uidp.GetString() : null;
                if (string.IsNullOrWhiteSpace(userId))
                {
                    Console.WriteLine(" [WARN] 使用者 id 為空,無法清理群組。");
                    return;
                }
            }

            // 2) GET /me/memberOf
            using var req = new HttpRequestMessage(HttpMethod.Get, EP.MemberOf);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await _http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode)
            {
                Console.WriteLine($" [WARN] 讀取 memberOf 失敗:{resp.StatusCode} {text}");
                return;
            }

            using var doc = JsonDocument.Parse(text);
            if (!doc.RootElement.TryGetProperty("value", out var arr)) return;

            int removedCount = 0;
            foreach (var item in arr.EnumerateArray())
            {
                // 只處理 @odata.type 為 #microsoft.graph.group 的項目
                if (item.TryGetProperty("@odata.type", out var typeEl))
                {
                    string? typeVal = typeEl.GetString();
                    if (typeVal != "#microsoft.graph.group") continue; // 略過非群組的 directoryObject
                }

                string displayName = item.TryGetProperty("displayName", out var dnp) ? (dnp.GetString() ?? "") : "";
                if (!StartsWithAny(displayName, prefixes)) continue;

                string? groupId = item.TryGetProperty("id", out var gidp) ? gidp.GetString() : null;
                if (string.IsNullOrWhiteSpace(groupId)) continue;

                // 3) DELETE /groups/{groupId}/members/{userId}/$ref
                using var delReq = new HttpRequestMessage(HttpMethod.Delete, EP.RemoveMemberRef(groupId!, userId!));
                delReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                using var delResp = await _http.SendAsync(delReq);
                if (delResp.IsSuccessStatusCode || delResp.StatusCode == HttpStatusCode.NoContent)
                {
                    Console.WriteLine($" [OK] 已退出群組:{displayName} (id={groupId})");
                    removedCount++;
                }
                else
                {
                    var errText = await delResp.Content.ReadAsStringAsync();
                    Console.WriteLine($" [WARN] 退出群組 {displayName} 失敗:{delResp.StatusCode} {errText}");
                }

                await DelayAsync(_cfg?.Run?.ApiDelay);
            }

            if (removedCount > 0)
                Console.WriteLine($" [INFO] 共退出 {removedCount} 個群組。");
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [WARN] 清理 Groups 例外:{ex.Message}");
        }
    }

    // ============== Helpers ==============
    private static void Shuffle<T>(IList<T> list)
    {
        for (int i = list.Count - 1; i > 0; i--)
        {
            int j = _rng.Next(i + 1);
            (list[i], list[j]) = (list[j], list[i]);
        }
    }

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
        // default fallback
        return 5;
    }

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

    private static string PickRandomPrefix(List<string> prefixes)
    {
        if (prefixes == null || prefixes.Count == 0) return "CYKJ";
        int idx = _rng.Next(prefixes.Count);
        return prefixes[idx];
    }

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


public partial class Config
{
    public List<Config.AccountConfig> Accounts { get; set; } = new();
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
        public bool UseExtendedApis { get; set; } = true;
    }

    public partial class WriteFeatures
    {
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










    



// ============== JSON Source Generator Context ==============
[JsonSourceGenerationOptions(
    PropertyNameCaseInsensitive = true,
    WriteIndented = false
)]
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
