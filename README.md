# Malware Analysis Lab –  MN (C++)

**Author:** Đào Minh Nghĩa  
**Focus:** Malware Analysis, Detection Engineering, Purple Team

---

## 📌 Giới thiệu

Repository này chứa phân tích kỹ thuật chi tiết về **MN** – một malware đa chức năng viết bằng C++ cho Windows, với các module: Telegram C2, ransomware, keylogger, password grabber, và persistence.

Mục tiêu: **hiểu cách malware hoạt động để xây dựng phòng thủ hiệu quả** (Purple Team).

---
## 🔍 Kỹ thuật nổi bật

| Kỹ thuật | Mô tả |
|----------|-------|
| **Anti-analysis** | IsDebuggerPresent, PEB, VM detection (MAC, RAM, CPU), timing attack |
| **Evasion** | AMSI patching, ETW patching |
| **Persistence** | Registry Run key, Startup folder, Scheduled task |
| **C2** | Telegram Bot API (domain hợp pháp) |
| **Process Hollowing** | Inject vào explorer.exe |
| **Ransomware** | XOR encryption, VSS deletion, Defender disable |
| **Stealer** | Chrome DPAPI, Discord token, WiFi profiles |

---

## 🛡️ Phát hiện

### YARA
```yara
rule MN_Strings {
    strings:
        $c2 = "api.telegram.org/bot"
        $persist = "WindowsUpdate"
        $shadow = "vssadmin delete shadows"
    condition:
        any of them
}
# Phân tích  MN Malware

## 1. Anti-Debug
- `IsDebuggerPresent()`: API chuẩn
- PEB BeingDebugged: đọc trực tiếp từ Process Environment Block
- Timing attack: `__rdtsc()` phát hiện debugger

## 2. Anti-VM
- MAC address: VMware (000C29, 005056)
- CPU cores < 2
- RAM < 2GB

## 3. Evasion
```cpp
// AMSI patch: AmsiScanBuffer → trả về 0x80070057
BYTE patch_amsi[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

// ETW patch: EtwEventWrite → trả về 0
BYTE patch_etw[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };
