

#include <iostream>
#include <string>
#include <windows.h>
#include <winhttp.h>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <random>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

using namespace std;

// ======================== ألوان ========================
void SetGreen() { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10); }
void SetRed() { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12); }
void SetYellow() { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14); }
void SetCyan() { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11); }
void SetWhite() { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7); }

// ======================== HMAC-SHA256 (بدون DeriveKey) ========================

string HMAC_SHA256(const string& key, const string& data) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTHASH hHmac = 0;
    BYTE hash[32];
    DWORD hashLen = 32;

    // Get crypto provider
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET);
    }

    // Create HMAC hash object directly (no DeriveKey!)
    if (!CryptCreateHash(hProv, CALG_HMAC, 0, 0, &hHmac)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Set HMAC key
    HMAC_INFO hmacInfo;
    ZeroMemory(&hmacInfo, sizeof(hmacInfo));
    hmacInfo.HashAlgid = CALG_SHA_256;

    if (!CryptSetHashParam(hHmac, HP_HMAC_INFO, (BYTE*)&hmacInfo, 0)) {
        CryptDestroyHash(hHmac);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Hash the key
    if (!CryptHashData(hHmac, (BYTE*)key.c_str(), (DWORD)key.length(), 0)) {
        CryptDestroyHash(hHmac);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Hash the data
    if (!CryptHashData(hHmac, (BYTE*)data.c_str(), (DWORD)data.length(), 0)) {
        CryptDestroyHash(hHmac);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Get result
    if (!CryptGetHashParam(hHmac, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHmac);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    CryptDestroyHash(hHmac);
    CryptReleaseContext(hProv, 0);

    // Convert to hex
    stringstream ss;
    for (DWORD i = 0; i < hashLen; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// ======================== دوال مساعدة ========================

string GenerateNonce() {
    random_device rd;
    mt19937_64 gen(rd());
    uniform_int_distribution<unsigned long long> dis;
    stringstream ss;
    ss << hex << dis(gen);
    return ss.str();
}

string GetTimestamp() {
    return to_string(time(nullptr));
}

string GetMachineHWID() {
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);

    DWORD volumeSerial;
    GetVolumeInformationA("C:\\", NULL, 0, &volumeSerial, NULL, NULL, NULL, 0);

    stringstream ss;
    ss << hex << volumeSerial << "-" << computerName;
    return ss.str();
}

// ======================== إرسال الطلب ========================

string SendRequest(const string& apiUrl, const string& appKey,
    const string& action, const string& jsonBody) {

    // Parse URL
    URL_COMPONENTS urlComp = { 0 };
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t hostName[256] = { 0 };
    wchar_t urlPath[512] = { 0 };

    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = 512;

    wstring wUrl = wstring(apiUrl.begin(), apiUrl.end());

    if (!WinHttpCrackUrl(wUrl.c_str(), 0, 0, &urlComp)) {
        return "{\"ok\":false,\"error\":\"Invalid URL\"}";
    }

    // Open session
    HINTERNET hSession = WinHttpOpen(L"HexaAuth/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        NULL, NULL, 0);
    if (!hSession) return "{\"ok\":false,\"error\":\"No session\"}";

    // Connect
    HINTERNET hConnect = WinHttpConnect(hSession, hostName, urlComp.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "{\"ok\":false,\"error\":\"Cannot connect\"}";
    }

    // Build path
    wstring path = L"/api.php?action=" + wstring(action.begin(), action.end());

    // Create request
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(),
        NULL, NULL, NULL,
        urlComp.nScheme == INTERNET_SCHEME_HTTPS ?
        WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "{\"ok\":false,\"error\":\"No request\"}";
    }

    // Timeout
    WinHttpSetTimeouts(hRequest, 30000, 30000, 30000, 30000);

    // ========== حساب التوقيع (نفس طريقة PHP) ==========
    string timestamp = GetTimestamp();
    string nonce = GenerateNonce();
    string method = "POST";
    string fullPath = "/api.php?action=" + action;

    // Build string to sign (مطابق لـ PHP)
    string stringToSign = timestamp + "\n" + nonce + "\n" + method + "\n" + fullPath + "\n" + jsonBody;

    // Calculate signature
    string signature = HMAC_SHA256(appKey, stringToSign);

    // Debug
    SetYellow();
    cout << "\n=== DEBUG ===" << endl;
    cout << "Timestamp: " << timestamp << endl;
    cout << "Nonce: " << nonce << endl;
    cout << "Method: " << method << endl;
    cout << "Path: " << fullPath << endl;
    cout << "Body: " << jsonBody << endl;
    cout << "StringToSign: " << stringToSign << endl;
    cout << "Signature: " << signature << endl;
    cout << "=============" << endl;
    SetWhite();

    // Build headers
    string headers = "Content-Type: application/json\r\n";
    headers += "X-App-Key: " + appKey + "\r\n";
    headers += "X-Timestamp: " + timestamp + "\r\n";
    headers += "X-Nonce: " + nonce + "\r\n";
    headers += "X-Signature: " + signature + "\r\n";

    wstring wHeaders = wstring(headers.begin(), headers.end());

    // Send request
    BOOL result = WinHttpSendRequest(hRequest, wHeaders.c_str(),
        (DWORD)wHeaders.length(),
        (LPVOID)jsonBody.c_str(),
        (DWORD)jsonBody.length(),
        (DWORD)jsonBody.length(), 0);

    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "{\"ok\":false,\"error\":\"Send failed\"}";
    }

    // Receive response
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "{\"ok\":false,\"error\":\"Receive failed\"}";
    }

    // Read response
    string response;
    DWORD bytesRead = 0;
    char buffer[4096];

    while (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = 0;
        response += buffer;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}

// ======================== Main ========================

int main() {
    system("title HexaAuth License Checker");

    SetCyan();
    cout << "========================================" << endl;
    cout << "      HexaAuth License Checker          " << endl;
    cout << "========================================" << endl;
    SetWhite();
    cout << endl;

    // ========== الإعدادات (غيرها حسب بياناتك) ==========
    string apiUrl = "https://hexaauth.alwaysdata.net/api.php";
    string appKey = "f3e31920adb1a8da9311396896f4c413";  // من جدول applications (secret_key)
    // =================================================

    SetYellow();
    cout << "[i] API URL: " << apiUrl << endl;
    cout << "[i] App Key: " << appKey << endl;
    SetWhite();
    cout << endl;

    // HWID
    string hwid = GetMachineHWID();
    SetCyan();
    cout << "Machine HWID: " << hwid << endl << endl;
    SetWhite();

    // License key
    SetCyan();
    cout << "Enter License Key: ";
    SetWhite();

    string licenseKey;
    getline(cin, licenseKey);

    if (licenseKey.empty()) {
        SetRed();
        cout << "[ERROR] License key required!" << endl;
        SetWhite();
        cout << "Press Enter to exit...";
        cin.get();
        return 1;
    }

    cout << endl;

    // Validate
    SetCyan();
    cout << "Validating license..." << endl;
    SetWhite();
    cout << endl;

    string jsonBody = "{\"license_key\":\"" + licenseKey + "\"";
    if (!hwid.empty()) {
        jsonBody += ",\"hwid\":\"" + hwid + "\"";
    }
    jsonBody += "}";

    string response = SendRequest(apiUrl, appKey, "validate", jsonBody);

    SetYellow();
    cout << "\nResponse: " << response << endl;
    SetWhite();

    // Check result
    if (response.find("\"valid\":true") != string::npos) {
        SetGreen();
        cout << "\n✅ LICENSE IS VALID!" << endl;
        SetWhite();
    }
    else if (response.find("\"valid\":false") != string::npos) {
        SetRed();
        cout << "\n❌ LICENSE INVALID!" << endl;
        SetWhite();

        // Extract reason
        size_t pos = response.find("\"reason\":\"");
        if (pos != string::npos) {
            pos += 10;
            size_t end = response.find("\"", pos);
            if (end != string::npos) {
                cout << "Reason: " << response.substr(pos, end - pos) << endl;
            }
        }
    }
    else {
        SetRed();
        cout << "\n❌ ERROR: " << response << endl;
        SetWhite();
    }

    cout << endl;
    cout << "Press Enter to exit...";
    cin.get();

    return 0;
}
