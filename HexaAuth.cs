using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Management;
using System.Security.Cryptography;
using System.Diagnostics;

// ==========================
// License Data Class
// ==========================
public class HexaLicenseData
{

    public string LicenseKey { get; set; }
    public string Status { get; set; }
    public string Plan { get; set; }
    public int? PlanId { get; set; }
    public int? ResellerId { get; set; }
    public string CustomData { get; set; }
    public string Note { get; set; }
    public string ExpiryDate { get; set; }
    public string CreatedAt { get; set; }
    public string UsedAt { get; set; }
    public int UsedCount { get; set; }
    public string HWID { get; set; }
    public int MaxDevices { get; set; }
    public int DeviceCount { get; set; }
    public string LastUsedIp { get; set; }
    public string Country { get; set; }
    public bool IsOneTimeUse { get; set; }
    public bool RenewalEnabled { get; set; }
    public int? RemainingTime { get; set; }

   public string RESET_PASSWOD_URL = "https://hexaauth.alwaysdata.net/reset_password.php";
}



public class HexaAuthTime
{
    public string FormatRemainingTime(string createdAt, string expiryDate)
    {
        // نحاول نحول النصوص إلى DateTime
        if (DateTime.TryParse(createdAt, out DateTime created) &&
            DateTime.TryParse(expiryDate, out DateTime expiry))
        {
            TimeSpan remaining = expiry - DateTime.Now;

           

            return $"{remaining.Days}d {remaining.Hours}h {remaining.Minutes}m {remaining.Seconds}s";
        }
        return "Invalid date";
    }
}

    // ==========================
    // License Response Class
    // ==========================
    public class HexaAuthResponse
    {
        public string Status { get; set; }
        public string Message { get; set; }
        public HexaLicenseData Data { get; set; }
    }

    // ==========================
    // HexaAuth Client
    // ==========================
    public class HexaAuthClient
    {
        private readonly string _apiUrl;
        private readonly string _secret;
        private readonly HttpClient _httpClient;

        public HexaAuthClient(string apiUrl, string appSecret)
        {
            _apiUrl = apiUrl;
            _secret = appSecret;
            _httpClient = new HttpClient();
        }

        private string GenerateHWID()
        {
            string cpu = GetWMI("Win32_Processor", "ProcessorId");
            string disk = GetWMI("Win32_DiskDrive", "SerialNumber");
            string mb = GetWMI("Win32_BaseBoard", "SerialNumber");
            string mac = GetWMI("Win32_NetworkAdapterConfiguration", "MACAddress");

            string combined = $"{cpu}-{disk}-{mb}-{mac}";
            var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(combined));
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }


    // دالة لحساب الوقت المتبقي


    private string GetWMI(string wmiClass, string wmiProperty)
        {
            try
            {
                var searcher = new ManagementObjectSearcher($"SELECT {wmiProperty} FROM {wmiClass}");
                foreach (var obj in searcher.Get())
                {
                    return obj[wmiProperty]?.ToString() ?? "";
                }
            }
            catch { }
            return "";
        }

        public async Task<JsonElement> PostAsync(object postData)
        {
            var content = new StringContent(JsonSerializer.Serialize(postData), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync(_apiUrl, content);
            var jsonResponse = await response.Content.ReadAsStringAsync();
            var doc = JsonDocument.Parse(jsonResponse);
            return doc.RootElement;
        }

        // ====================
        // Signup
        // ====================
        public async Task<(bool Success, string Message, int? ClientId, string Username, string Email)> SignupAsync(
          string username, string email, string password, string licenseKey)
        {
            var postData = new
            {
                action = "signup",
                username,
                email,
                password,
                license_key = licenseKey
            };

            try
            {
                var resultElem = await PostAsync(postData);
                bool success = resultElem.GetProperty("status").GetString().ToLower() == "success";
                string message = resultElem.GetProperty("message").GetString();
                int? clientId = null;
                string uname = null;
                string uemail = null;

                if (success && resultElem.TryGetProperty("data", out JsonElement dataElem))
                {
                    if (dataElem.TryGetProperty("client_id", out JsonElement idElem) && idElem.ValueKind == JsonValueKind.Number)
                        clientId = idElem.GetInt32();
                    if (dataElem.TryGetProperty("username", out JsonElement userElem))
                        uname = userElem.GetString();
                    if (dataElem.TryGetProperty("email", out JsonElement emailElem))
                        uemail = emailElem.GetString();
                }

                return (success, message, clientId, uname, uemail);
            }
            catch (Exception ex)
            {
                return (false, $"Exception: {ex.Message}", null, null, null);
            }
        }

    // ضيف ده جوه نفس الـ class بتاعك


    // ====================
    // Login
    // ====================
    public async Task<(bool Success, string Message, int? ClientId, string Username, string Email)> LoginAsync(
            string usernameOrEmail, string password)
        {
            try
            {
                var postData = new
                {
                    action = "login",
                    username = usernameOrEmail,
                    password
                };

                var result = await PostAsync(postData);

                bool success = result.GetProperty("status").GetString().ToLower() == "success";
                string message = result.GetProperty("message").GetString();
                int? clientId = null;
                string uname = null;
                string uemail = null;

                if (success && result.TryGetProperty("data", out JsonElement data))
                {
                    if (data.TryGetProperty("client_id", out JsonElement idElem))
                        clientId = idElem.GetInt32();
                    if (data.TryGetProperty("username", out JsonElement userElem))
                        uname = userElem.GetString();
                    if (data.TryGetProperty("email", out JsonElement emailElem))
                        uemail = emailElem.GetString();
                }

                return (success, message, clientId, uname, uemail);
            }
            catch (Exception ex)
            {
                return (false, $"Exception: {ex.Message}", null, null, null);
            }
        }

        // ====================
        // Get License Info (linked to client)
        // ====================
        public async Task<HexaAuthResponse> GetLicenseInfoAsync(int clientId, string licenseKey)
        {
            try
            {
                var postData = new
                {
                    action = "get_license_info",
                    client_id = clientId,
                    license_key = licenseKey
                };

                var resultElem = await PostAsync(postData);

                if (resultElem.GetProperty("status").GetString().ToLower() != "success")
                {
                    return new HexaAuthResponse
                    {
                        Status = resultElem.GetProperty("status").GetString(),
                        Message = resultElem.GetProperty("message").GetString(),
                        Data = null
                    };
                }

                HexaLicenseData licenseData = JsonSerializer.Deserialize<HexaLicenseData>(
                    resultElem.GetProperty("data").GetRawText(),
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                );

                return new HexaAuthResponse
                {
                    Status = "success",
                    Message = "License info retrieved",
                    Data = licenseData
                };
            }
            catch (Exception ex)
            {
                return new HexaAuthResponse
                {
                    Status = "error",
                    Message = $"Exception: {ex.Message}",
                    Data = null
                };
            }
        }

        // ====================
        // Validate License (original)
        // ====================
        public async Task<HexaAuthResponse> ValidateLicenseAsync(string licenseKey)
        {
            try
            {
                var hwid = GenerateHWID();
                var postData = new
                {
                    app_key = _secret,
                    license_key = licenseKey,
                    hwid = hwid
                };

                var resultElem = await PostAsync(postData);

                string status = resultElem.GetProperty("status").GetString();
                string message = resultElem.GetProperty("message").GetString();

                HexaLicenseData licenseData = null;
                if (status.ToLower() == "success" && resultElem.TryGetProperty("data", out JsonElement dataElem))
                {
                    licenseData = JsonSerializer.Deserialize<HexaLicenseData>(
                        dataElem.GetRawText(),
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                }

                return new HexaAuthResponse
                {
                    Status = status,
                    Message = message,
                    Data = licenseData
                };
            }
            catch (Exception ex)
            {
                return new HexaAuthResponse
                {
                    Status = "error",
                    Message = $"Exception: {ex.Message}",
                    Data = null
                };
            }
        }

    }

