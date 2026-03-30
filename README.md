# Malware Analysis Lab –  MN (C++)

**Author:** Đào Minh Nghĩa  
**Focus:** Malware Analysis, Detection Engineering, Purple Team

---

## 📌 Giới thiệu

Repository này chứa phân tích kỹ thuật chi tiết về **WormGPT** – một malware đa chức năng viết bằng C++ cho Windows, với các module: Telegram C2, ransomware, keylogger, password grabber, và persistence.

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
