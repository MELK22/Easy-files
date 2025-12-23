# MetaCrypt - Quick Start Guide

## 🚀 Installation

### Prerequisites
- **Python 3.9 or higher** ([Download Python](https://www.python.org/downloads/))
- pip (comes with Python)

### Step-by-Step Installation

1. **Download the files:**
   - `metacrypt_gui.py` (main application)
   - `requirements.txt` (dependencies)

2. **Open terminal/command prompt** in the folder containing the files

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```bash
   python metacrypt_gui.py
   ```

### Installation Notes

**Windows:**
```cmd
# May need to use python3 or py
py -3 metacrypt_gui.py
```

**macOS/Linux:**
```bash
# May need python3
python3 metacrypt_gui.py
```

**If you get "command not found":**
- Make sure Python is added to your PATH
- On Windows, try `py -3` instead of `python`
- On macOS/Linux, try `python3` instead of `python`

---

## 📖 How to Use

### Embedding Secret Data (Hiding Data)

1. **Launch the application**
   ```bash
   python metacrypt_gui.py
   ```

2. **Go to "📝 Embed Data" tab**

3. **Select your file:**
   - Click **"📁 Browse"** in Step 1
   - Choose a PNG, JPEG, PDF, MP3, or MP4 file
   - Output location will be auto-suggested

4. **Enter your secret data:**
   - Type directly in the text box, OR
   - Click **"📄 Load File"** to embed a file's contents

5. **Enter a password:**
   - Use a strong password (20+ characters recommended)
   - **IMPORTANT:** You'll need this exact password to decrypt later!
   - Check "Show" if you want to see what you're typing

6. **Click "🔒 Embed & Encrypt Data"**
   - Wait for the progress bar to complete
   - You'll see a success message with the output file location

7. **Done!** Your encrypted data is now hidden in the file's metadata

### Extracting Hidden Data (Revealing Data)

1. **Go to "🔓 Extract Data" tab**

2. **Select the file:**
   - Click **"📁 Browse"**
   - Choose the file with embedded data

3. **Enter the password:**
   - Must be the exact same password used when embedding
   - Check "Show" if needed

4. **Click "🔓 Extract & Decrypt Data"**
   - The decrypted data appears in the text area
   - If wrong password: you'll see an error

5. **Save the data (optional):**
   - Click **"💾 Save to File"** to save the extracted data

---

## ✅ Example Workflow

### Example 1: Hide a Password in an Image

```
1. Take a photo (photo.jpg)
2. Launch MetaCrypt
3. Embed tab → Select photo.jpg
4. Enter: "My WiFi password is: SuperSecret123!"
5. Password: "MyStrongPassword2024"
6. Save as: photo_encrypted.jpg
7. Share photo_encrypted.jpg (password is hidden inside!)
```

### Example 2: Hide API Keys in a PDF

```
1. Have a document (report.pdf)
2. Launch MetaCrypt
3. Embed tab → Select report.pdf
4. Enter your API key or credentials
5. Password: "CompanySecretKey2024"
6. Save as: report_encrypted.pdf
7. Only those with the password can extract the API key
```

---

## 🔐 Security Features

- **AES-256-GCM Encryption:** Military-grade encryption
- **Argon2id Key Derivation:** Resists brute-force attacks
- **Unique Nonces:** Each encryption is unique
- **Tamper Detection:** Modified data won't decrypt
- **No Hardcoded Keys:** Everything derived from your password

---

## ⚠️ Important Warnings

### Password Management
- **If you forget the password, data CANNOT be recovered**
- Use a password manager
- Consider keeping a secure backup of important passwords

### Metadata Stripping
- Social media (Facebook, Instagram, Twitter) **strips metadata**
- Some image editors remove metadata
- PDF optimizers may strip metadata
- **Always test** with your specific workflow

### Size Limitations
- Keep embedded data under **64 KB** for best compatibility
- Larger data may work but could cause issues
- The app will warn you about large files

### Not Steganography
- Data is stored in **visible metadata fields**
- Anyone with metadata viewer can see something is there
- It's encrypted, but not hidden
- Use cases: legitimate data embedding, not covert communication

---

## 📋 Supported File Formats

| Format | Metadata Field | Size Limit | Notes |
|--------|---------------|------------|-------|
| PNG | tEXt chunks | ~1 MB | Best choice for images |
| JPEG/JPG | COM markers | ~48 KB | Widely supported |
| PDF | Info dictionary | ~1 MB | Good for documents |
| MP3 | ID3v2 tags | ~1 MB | Standard audio format |
| MP4/M4A | Metadata atoms | ~1 MB | Video and audio |

---

## 🐛 Troubleshooting

### "Module not found" error
```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

### "Not a valid [format] file"
- Make sure the file is actually the format you think it is
- Try opening it in another application first
- The file might be corrupted

### "No embedded data found"
- Make sure you selected the correct file
- The file might not have any embedded data
- Metadata may have been stripped by another application

### "Wrong password or corrupted data"
- Double-check your password (passwords are case-sensitive!)
- The data might have been tampered with
- Metadata might have been modified by another application

### GUI doesn't open
- Check that PySide6 installed correctly: `pip show PySide6`
- Try reinstalling: `pip uninstall PySide6` then `pip install PySide6`
- Make sure you're using Python 3.9+

---

## 💡 Best Practices

1. **Test First:** Always test that embedded data survives your workflow
2. **Strong Passwords:** Use 20+ character passwords with mix of characters
3. **Small Data:** Keep under 64 KB when possible
4. **Backup:** Keep backups of important data
5. **Document:** Note which files have embedded data
6. **Verify:** After embedding, immediately extract to verify it works

---

## 📝 Use Cases

### ✅ Good Use Cases
- Embedding license keys in software installers
- Storing configuration data in media files
- Adding encrypted notes to documents
- Hiding passwords in local files
- Watermarking with encrypted metadata

### ❌ Not Suitable For
- Social media uploads (metadata stripped)
- Covert communication (not truly hidden)
- Critical security applications (better tools exist)
- Large data storage (size limitations)
- Guaranteed persistence (metadata can be removed)

---

## 🆘 Getting Help

### Check the Help Tab
The application includes a comprehensive help tab with:
- Detailed usage instructions
- Security information
- Limitations and warnings
- Technical details

### Common Questions

**Q: Is this secure?**
A: Yes, the cryptography (AES-256-GCM + Argon2id) is secure. Security depends on your password strength.

**Q: Can I hide any type of file?**
A: You can embed any data, but the *container* must be PNG, JPEG, PDF, MP3, or MP4.

**Q: Will this work with [specific application]?**
A: Test it! Different applications handle metadata differently.

**Q: How do I know if metadata was preserved?**
A: Try extracting immediately after embedding to verify.

---

## 🎯 Quick Command Reference

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python metacrypt_gui.py

# On Windows
py -3 metacrypt_gui.py

# On macOS/Linux
python3 metacrypt_gui.py
```

---

## 📦 What You Need

**Files:**
- `metacrypt_gui.py` - The main application (single file!)
- `requirements.txt` - List of dependencies

**Python Packages (installed automatically):**
- PySide6 - GUI framework
- cryptography - Encryption
- argon2-cffi - Password hashing
- Pillow - Image handling
- PyPDF2 - PDF metadata
- mutagen - Audio/video metadata

---

## ✨ Features at a Glance

✅ Modern, user-friendly GUI
✅ Cross-platform (Windows, macOS, Linux)
✅ Military-grade encryption (AES-256)
✅ Multiple file format support
✅ Progress indicators
✅ Clear error messages
✅ Password visibility toggle
✅ Auto-suggested output paths
✅ File size warnings
✅ Comprehensive help system

---

## 🎉 You're Ready!

That's it! You now have a fully functional encrypted metadata embedding system.

**Next Steps:**
1. Install Python and dependencies
2. Run `python metacrypt_gui.py`
3. Try embedding and extracting with a test file
4. Read the in-app help for more details

**Remember:**
- 🔑 Use strong passwords
- 📦 Keep data small (under 64KB)
- 🧪 Test your workflow
- 💾 Keep backups

Enjoy using MetaCrypt! 🔒
