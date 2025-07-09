# 🛡️ VST_HashCheck

**VST_HashCheck** is a Python-based command-line tool to check file hashes (MD5, SHA1, SHA256) against [VirusTotal](https://www.virustotal.com/)'s database. It supports batching, API rate-limiting, response caching, and gives a detailed summary of malicious and suspicious hashes.

---

## 🔍 Features

- 🔑 VirusTotal API integration
- ⚙️ Caches results to avoid duplicate queries
- ⏱️ Respects API rate limits with wait logic
- 📊 Progress bar for large lists of hashes
- 🧾 Batch output every N hashes
- ✅ Final summary showing:
  - Malicious hashes with detection score
  - Suspicious hashes list

---

## 📦 Requirements

- Python 3.7+
- Modules:
  - `requests`
  - `tqdm` (for progress bar)
  - `tabulate` (for table output)

Install dependencies:

```
pip install requests tqdm tabulate
```
## 🔐 API Key Setup

You need a free VirusTotal API key:

- Register at: https://www.virustotal.com/gui/join-us  
- Get your API key from: https://www.virustotal.com/gui/user/apikey  

Set it in your environment:

**Linux/macOS:**

```bash
export VT_API_KEY="your_api_key"
```

**Windows Powershell:**
```
$env:VT_API_KEY = "your_api_key"
```

## 🚀 Usage

**Check a file of hashes**
```
python VST_HashCheck.py --file Hashfile.txt --batch 10
```
**JSON output instead of table**
```
python VST_HashCheck.py --file hashes.txt --output json
```
## 📊 Example Summary Output

```
========== SUMMARY ==========
Total hashes checked: 20
Malicious: 3
Suspicious: 2

[!] Malicious hashes (malicious/total):
  - b4b147bc522828731f1a016bfa72c073  (8/66)
  - 6f5902ac237024bdd0c176cb93063dc4  (2/71)
  - 5d41402abc4b2a76b9719d911017c592  (15/65)

[!] Suspicious hashes:
  - 7c5aba41f53293b712fd86d08ed5b36e
  - 9ae0ea9e3c9c6e1b9b6252c8395efdc1
```
