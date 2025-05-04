<img width="600" src="https://github.com/user-attachments/assets/019bed2a-d5a3-4c26-89b4-53583f8e0ef3" alt="Tor Logo onion and fingers logging into Tor browser"/>



# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/chiprojects/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management has observed irregular patterns in encrypted network traffic, including connections to IP addresses associated with known Tor entry nodes. As a result, the team suspects that some employees might be utilizing the Tor Browser to bypass network security controls. Additionally, there have been anonymous reports indicating that certain staff members are discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage within the organization's network and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management immediately.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "cyberwoman" downloaded a TOR installer. Additionally, multiple TOR-related files were copied to the desktop, and a file called `tor-shopping-list.txt` was created on the desktop at `2025-05-02T01:05:13.6598946Z`. These events began at `2025-04-29T15:52:36.0881443Z`.

**Query used to locate events:**

```kql

DeviceFileEvents
|where DeviceName == "chithreathunter"
|where FileName contains "tor"
|order by Timestamp desc
|where InitiatingProcessAccountName == "cyberwoman"
|where Timestamp >= datetime(2025-04-29T15:52:36.0881443Z)
|project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

![image](https://github.com/user-attachments/assets/21b5cb3d-5c15-4497-8aec-2a51d726c9a9)
![image](https://github.com/user-attachments/assets/a24e1d08-6b05-4bda-aaf9-5c1d05f6e393)
![image](https://github.com/user-attachments/assets/18ad2b20-600d-421a-9920-e573ec44562d)
![image](https://github.com/user-attachments/assets/5b8dcb68-6477-4be3-b944-2a0ee1aa1c93)
![image](https://github.com/user-attachments/assets/5b78eea9-eb4f-48e2-bd7d-00d7c86756fc)
![image](https://github.com/user-attachments/assets/c9be7b12-a875-49d1-bd88-8311d064428a)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.1.exe". Based on the logs returned, at `2025-04-30T21:40:41.3321335Z`, employee `cyberwoman` on the "chithreathunter" device ran the file `tor-browser-windows-x86_64-portable-14.5.1.exe` from their Downloads folder, using a command `/S` that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
|where DeviceName == 'chithreathunter'
|where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.1.exe"
|project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```

![image](https://github.com/user-attachments/assets/1f9a001d-b7e5-4e5f-85bc-576915283aad)

↙️Snapshot of ProcessCommandLine

![image](https://github.com/user-attachments/assets/e7f7f934-b9f5-4ca9-8e56-56879a3cc3c3)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that the user "cyberwoman" actually opened the TOR browser. There was evidence that the Tor browser was opened at `2025-04-30T21:45:02.3003707Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` initiated afterwards. 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == 'chithreathunter'
| where FileName has_any ("tor.exe", "firefox.exe", "tor.browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/9bebf50e-4d63-4181-9292-0aa7fa6d77d7)
![image](https://github.com/user-attachments/assets/2e75973f-e8d9-41c1-a8c5-35685476a3f3)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication of the TOR browser being used to establish a connection using any of the known TOR ports. At `2025-04-30T22:08:36.9782232Z`, an employee on the "chithreathunter" device successfully established a connection to the remote IP address `94.16.122.61` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder: `c:\users\cyberwoman\desktop\torbrowser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`, however, the connection was not successful.

**Query used to locate events:**

```kql
DeviceNetworkEvents
|where DeviceName == "chithreathunter"
|where InitiatingProcessAccountName != "system"
|where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, RemoteUrl, InitiatingProcessFolderPath
| where RemotePort in ("9150", "9001", "9030", "9040", "9050", "9051", "80", "443")
| order by Timestamp desc 
```
![image](https://github.com/user-attachments/assets/c017c59c-2985-4f2f-94cc-26579529a795)

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-04-29T15:52:36.0881443Z`
- **Event:** The user "cyberwoman" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\Cyberwoman\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-04-30T21:40:41.3321335Z`
- **Event:** The user "cyberwoman" executed the file `tor-browser-windows-x86_64-portable-14.5.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.1.exe /S`
- **File Path:** `C:\Users\Cyberwoman\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-04-30T21:45:02.3003707Z`
- **Event:** User "cyberwoman" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\Cyberwoman\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-04-30T22:08:36.9782232Z`
- **Event:** A network connection to IP `94.16.122.61` on port `9001` by user "cyberwoman" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\cyberwoman\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-04-30T22:08:56.290079Z` - Connection attempt to `165.73.242.163` on port `443`.
  - `2025-04-30T22:09:03.0492554Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful and failed connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-05-02T01:05:13.6598946Z`
- **Event:** The user "cyberwoman" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Cyberwoman\Documents\tor-shopping-list.txt`

---

## Summary

The user "cyberwoman" on the "chithreathunter" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and create various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `chithreathunter` by the user `cyberwoman`. The device was isolated, and the user's direct manager was notified.

---
