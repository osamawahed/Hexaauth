using System;
using System.Threading.Tasks;


class Program
{
    static async Task Main(string[] args)
    {
        var client = new HexaAuthClient("https://hexaauth.alwaysdata.net/api.php", "app-secret");

        var result = await client.ValidateLicenseAsync("Key");

        if (result.Status == "success")
        {
            Console.WriteLine("? License Valid");
            Console.WriteLine($"Plan: {result.Data.Plan}");
            Console.WriteLine($"HWID: {result.Data.HWID}");
            Console.WriteLine($"Status: {result.Data.Status}");
            Console.WriteLine($"Note: {result.Data.Note}");
            Console.WriteLine($"Used Count: {result.Data.UsedCount}");
            Console.WriteLine($"Device Count: {result.Data.DeviceCount}/{result.Data.MaxDevices}");
            Console.WriteLine($"IP: {result.Data.LastUsedIp ?? "N/A"}");
            Console.WriteLine($"Country: {result.Data.Country}");
            Console.WriteLine($"Created At: {result.Data.CreatedAt ?? "N/A"}");
            Console.WriteLine($"Used At: {result.Data.UsedAt ?? "N/A"}");
            Console.WriteLine($"Expiry Date: {result.Data.ExpiryDate ?? "Never"}");

            Console.WriteLine($"Time Left: {HexaAuthClient.FormatRemainingTime(result.Data.CreatedAt, result.Data.ExpiryDate)}");




        }
        else
        {
            Console.WriteLine($"❌ Error: {result.Message}");
        }

    }

}

