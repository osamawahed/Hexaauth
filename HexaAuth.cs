using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Management;
using System.Security.Cryptography;
using System.Linq;

public class HexaLicenseData
{
    public string LicenseKey { get; set; }
    public string Status { get; set; }
    public string Plan { get; set; }
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
    public string TimezoneId { get; set; }

}

public class HexaAuthResponse
{
    public string Status { get; set; }
    public string Message { get; set; }
    public HexaLicenseData Data { get; set; }
}

public class HexaAuthClient
{
    private readonly string _apiUrl;
    private readonly string _secret;

    public HexaAuthClient(string apiUrl, string appSecret)
    {
        _apiUrl = apiUrl;
        _secret = appSecret;
    }

    public async Task<HexaAuthResponse> ValidateLicenseAsync(string licenseKey)
    {
        HttpClient client = new HttpClient();

        var hwid = GenerateHWID();
        var postData = new
        {
            app_key = _secret,
            license_key = licenseKey,
            hwid = hwid
        };

        var content = new StringContent(JsonSerializer.Serialize(postData), Encoding.UTF8, "application/json");

        try
        {
            HttpResponseMessage response = await client.PostAsync(_apiUrl, content);
            string jsonResponse = await response.Content.ReadAsStringAsync();

            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            var result = JsonSerializer.Deserialize<HexaAuthResponse>(jsonResponse, options);

            return result;
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

    public string GenerateHWID()
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
    public static string FormatRemainingTime(string createdAtUtc, string expiryDateUtc)
    {
        if (string.IsNullOrEmpty(expiryDateUtc) || expiryDateUtc.ToLower().Contains("never"))
            return "Never";

        if (DateTime.TryParse(createdAtUtc, null, System.Globalization.DateTimeStyles.AdjustToUniversal, out DateTime createdUtc) &&
            DateTime.TryParse(expiryDateUtc, null, System.Globalization.DateTimeStyles.AdjustToUniversal, out DateTime expUtc))
        {
          
            TimeSpan remaining = expUtc - DateTime.UtcNow;

            if (remaining.TotalSeconds <= 0)
                return "Expired";

            return $"{(int)remaining.TotalDays}d {remaining.Hours}h {remaining.Minutes}m {remaining.Seconds}s";
        }

        return "Invalid Date";
    }




}

