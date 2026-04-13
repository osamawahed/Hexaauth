using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Sodium;

namespace LicenseClient
{
    public class LicenseResponse
    {
        public bool ok { get; set; }
        public string error { get; set; }
        public string message { get; set; }
        public string request_id { get; set; }
        public string challenge { get; set; }
        public string expires_at { get; set; }
        public string device_uid { get; set; }
        public bool valid { get; set; }
        public string reason { get; set; }
        public bool is_new_device { get; set; }
        public bool hwid_bound { get; set; }
        public bool is_first_use { get; set; }
        public string server_time { get; set; }
        public AppInfoFull app_info { get; set; }
        public LicenseFull license { get; set; }
        public LicenseInfoFull license_info { get; set; }
        public DeviceInfo device { get; set; }
    }

    public class AppInfoFull
    {
        public string app_id { get; set; }
        public string name { get; set; }
        public int max_devices_per_license { get; set; }
        public int total_licenses { get; set; }
        public int total_devices { get; set; }
    }

    public class LicenseFull
    {
        public string key { get; set; }
        public string status { get; set; }
        public string expires_at { get; set; }
        public double? remaining_days { get; set; }
        public bool expiring_soon { get; set; }
        public int max_devices { get; set; }
        public int current_devices { get; set; }
        public string first_used_at { get; set; }
        public bool hwid_bound { get; set; }
        public List<DeviceInfo> devices { get; set; }
    }

    public class LicenseInfoFull
    {
        public string license_key { get; set; }
        public string status { get; set; }
        public string expires_at { get; set; }
        public int max_devices { get; set; }
        public int current_devices { get; set; }
        public double? remaining_days { get; set; }
    }

    public class DeviceInfo
    {
        public string uid { get; set; }
        public string device_uid { get; set; }
        public string platform { get; set; }
        public string first_seen { get; set; }
        public string last_seen { get; set; }
        public string status { get; set; }
    }

    public class ChallengeResult
    {
        public string Challenge { get; set; }
        public string ExpiresAt { get; set; }
        public string AppId { get; set; }
        public string AppName { get; set; }
    }

    public class RegisterResult
    {
        public bool Success { get; set; }
        public string DeviceUid { get; set; }
        public bool IsNewDevice { get; set; }
        public string AppId { get; set; }
        public string AppName { get; set; }
        public string LicenseKey { get; set; }
        public string LicenseStatus { get; set; }
        public string LicenseExpiresAt { get; set; }
        public int LicenseMaxDevices { get; set; }
        public int LicenseCurrentDevices { get; set; }
        public double? LicenseRemainingDays { get; set; }
    }

    public class ValidationResult
    {
        public bool IsValid { get; set; }
        public string ErrorCode { get; set; }
        public string ErrorMessage { get; set; }
        public string RequestId { get; set; }
        public string AppName { get; set; }
        public string LicenseKey { get; set; }
        public string LicenseStatus { get; set; }
        public string LicenseExpiresAt { get; set; }
        public double? LicenseRemainingDays { get; set; }
        public bool LicenseExpiringSoon { get; set; }
        public int LicenseMaxDevices { get; set; }
        public int LicenseCurrentDevices { get; set; }
        public string DeviceUid { get; set; }
        public string DeviceLastSeen { get; set; }
        public bool HwidBound { get; set; }
        public bool IsFirstUse { get; set; }

        public void Print()
        {
            if (!IsValid)
            {
                Console.WriteLine($"  ❌ INVALID: {ErrorCode}");
                Console.WriteLine($"  Message: {ErrorMessage}");
                return;
            }

            Console.WriteLine($"  ✅ LICENSE VALID");
            Console.WriteLine($"  ┌────────────────────────────────────────");
            Console.WriteLine($"  │ App: {AppName}");
            Console.WriteLine($"  │ License: {LicenseKey}");
            Console.WriteLine($"  │ Status: {LicenseStatus}");
            Console.WriteLine($"  │ Expires: {LicenseExpiresAt ?? "Never"}");
            Console.WriteLine($"  │ Remaining: {LicenseRemainingDays?.ToString("F1") ?? "N/A"} days");
            if (LicenseExpiringSoon)
                Console.WriteLine($"  │ ⚠️  WARNING: License expires soon!");
            Console.WriteLine($"  │ Devices: {LicenseCurrentDevices}/{LicenseMaxDevices}");
            Console.WriteLine($"  │ HWID Bound: {(HwidBound ? "Yes" : "No")}");
            if (IsFirstUse)
                Console.WriteLine($"  │ 🔒 First use - HWID bound to this device!");
            Console.WriteLine($"  │ Device: {DeviceUid?[..8]}...");
            Console.WriteLine($"  │ Last seen: {DeviceLastSeen}");
            Console.WriteLine($"  └────────────────────────────────────────");
        }
    }

    public class LicenseClient
    {
        private readonly HttpClient _http = new HttpClient();
        private readonly string _apiUrl;
        private readonly string _appSecret;

        public LicenseClient(string apiUrl, string appSecret)
        {
            _apiUrl = apiUrl;
            _appSecret = appSecret;
        }

        private string GetMachineHWID() // never change this method, it's used to generate a unique identifier for the machine based on hardware and environment info. You can modify it to add more identifiers if you want, but make sure to keep the same format and hashing method for compatibility with the server.
        {
            try
            {
                var cpu = Environment.ProcessorCount.ToString();
                var machineName = Environment.MachineName;
                var userName = Environment.UserName;
                var osVersion = Environment.OSVersion.ToString();

                string diskSerial = "UNKNOWN";
                try
                {
                    var drives = System.IO.DriveInfo.GetDrives();
                    foreach (var drive in drives)
                    {
                        if (drive.IsReady && drive.DriveType == System.IO.DriveType.Fixed)
                        {
                            diskSerial = drive.VolumeLabel ?? "DISK";
                            break;
                        }
                    }
                }
                catch { }

                var info = $"{cpu}|{machineName}|{userName}|{osVersion}|{diskSerial}";
                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(info));
                return Convert.ToBase64String(hash);
            }
            catch
            {
                return "UNKNOWN_" + Guid.NewGuid().ToString().Substring(0, 8);
            }
        }

        public async Task<(string deviceUid, byte[] privateKey)> Activate(string licenseKey)
        {
            
            var challengeRes = await Post("device.challenge", new { app_secret = _appSecret });
            string challenge = challengeRes.challenge;
            string appId = challengeRes.app_info?.app_id;
            string appName = challengeRes.app_info?.name;

            Console.WriteLine($"  App: {appName}");
            Console.WriteLine($"  License: {licenseKey}");

        
            var keyPair = PublicKeyAuth.GenerateKeyPair();
            var fingerprint = GenerateFingerprint();
            var fpHash = Sha256Hex(fingerprint);

           
            var message = $"device.register\n{challenge}\n{appId}\n{licenseKey}\nwindows\n{fpHash}";
            var signature = Convert.ToBase64String(PublicKeyAuth.SignDetached(Encoding.UTF8.GetBytes(message), keyPair.PrivateKey));
            var pubKey = Convert.ToBase64String(keyPair.PublicKey);

            // Register device
            var registerRes = await Post("device.register", new
            {
                app_secret = _appSecret,
                license_key = licenseKey,
                platform = "windows",
                fingerprint,
                public_key = pubKey,
                challenge,
                signature
            });

            string deviceUid = registerRes.device_uid;
            Console.WriteLine($"  Device ID: {deviceUid}");
            Console.WriteLine($"  Devices used: {registerRes.license_info?.current_devices}/{registerRes.license_info?.max_devices}");

            return (deviceUid, keyPair.PrivateKey);
        }

        public async Task<ValidationResult> ValidateLicense(string licenseKey, string deviceUid, byte[] privateKey)
        {
            var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var nonce = Convert.ToBase64String(Guid.NewGuid().ToByteArray()).Replace("+", "").Replace("/", "")[..16];
            var hwid = GetMachineHWID();

            var payload = new
            {
                app_secret = _appSecret,
                license_key = licenseKey,
                device_uid = deviceUid,
                hwid = hwid,
                device_ts = ts,
                device_nonce = nonce
            };

            var json = JsonConvert.SerializeObject(payload);
            var canonical = $"license.validate\n{ts}\n{nonce}\n{Sha256Hex(json)}";
            var sig = Convert.ToBase64String(PublicKeyAuth.SignDetached(Encoding.UTF8.GetBytes(canonical), privateKey));

            var res = await Post("license.validate", new
            {
                app_secret = _appSecret,
                license_key = licenseKey,
                device_uid = deviceUid,
                hwid = hwid,
                device_ts = ts,
                device_nonce = nonce,
                device_sig = sig
            });

            var result = new ValidationResult
            {
                IsValid = res.valid,
                ErrorCode = !res.valid ? res.error : null,
                ErrorMessage = !res.valid ? res.message ?? res.reason : null,
                RequestId = res.request_id,
                HwidBound = res.hwid_bound,
                IsFirstUse = res.is_first_use
            };

            if (res.valid)
            {
                result.AppName = res.app_info?.name;
                result.LicenseKey = licenseKey;
                result.LicenseStatus = res.license?.status ?? res.license_info?.status;
                result.LicenseExpiresAt = res.license?.expires_at ?? res.license_info?.expires_at;
                result.LicenseRemainingDays = res.license?.remaining_days ?? res.license_info?.remaining_days;
                result.LicenseExpiringSoon = res.license?.expiring_soon ?? false;
                result.LicenseMaxDevices = res.license?.max_devices ?? res.license_info?.max_devices ?? 0;
                result.LicenseCurrentDevices = res.license?.current_devices ?? res.license_info?.current_devices ?? 0;
                result.DeviceUid = deviceUid;
                result.DeviceLastSeen = res.device?.last_seen;
            }

            return result;
        }

        private async Task<LicenseResponse> Post(string action, object data)
        {
            var content = new StringContent(JsonConvert.SerializeObject(data), Encoding.UTF8, "application/json");
            var response = await _http.PostAsync($"{_apiUrl}?action={action}", content);
            var json = await response.Content.ReadAsStringAsync();
            var result = JsonConvert.DeserializeObject<LicenseResponse>(json);

            if (!result.ok && result.error != null)
                throw new Exception($"{result.error}: {result.message ?? result.reason}");

            return result;
        }

        private string Sha256Hex(string input)
        {
            using var sha = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(input);
            var hash = sha.ComputeHash(bytes);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        private string GenerateFingerprint()
        {
            var info = $"{Environment.MachineName}|{Environment.OSVersion}|{Environment.ProcessorCount}|{Environment.UserName}";
            using var sha = SHA256.Create();
            return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(info))).Replace("-", "").ToLower();
        }
    }

    class Program
    {
        static async Task Main()
        {
            Console.WriteLine("╔═══════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║             HexaAuth License Manager - C# Client              ║");
            Console.WriteLine("╚═══════════════════════════════════════════════════════════════╝\n");

            var apiUrl = "https://hexaauth.alwaysdata.net/api.php"; // Never Change this URL, it's the endpoint for all API requests 
            var appSecret = "976e*************e60"; // change this to your app secret from dashboard 
            var licenseKey = "****-ULOJ-****-S27G-****";  // this is the license key you want to validate , you can change the method to get this from user input or a config file

            var client = new LicenseClient(apiUrl, appSecret);

            try
            {
           
                Console.WriteLine("[1] Activating device...");
                var (deviceUid, privateKey) = await client.Activate(licenseKey);
                Console.WriteLine("✅ ACTIVATION COMPLETE!\n");

        
                Console.WriteLine("----------------------------------------");
                Console.WriteLine("        LICENSE STATUS");
                Console.WriteLine("----------------------------------------\n");

                var result = await client.ValidateLicense(licenseKey, deviceUid, privateKey);
                result.Print();

                if (!result.IsValid)
                {
                    Console.WriteLine($"\n⚠️ License is invalid or expired!");
                    Console.WriteLine($"Reason: {result.ErrorMessage}");
                }
                else if (result.LicenseExpiringSoon)
                {
                    Console.WriteLine($"\n⚠️ Your license will expire in {result.LicenseRemainingDays} days!");
                }
                else
                {
                    Console.WriteLine($"\n✅ Your license is valid until {result.LicenseExpiresAt}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error: {ex.Message}");
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}