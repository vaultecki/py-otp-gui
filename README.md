# ThaOTP - Secure OTP Manager

A secure, feature-rich One-Time Password (OTP) manager with encrypted storage, built with Python and Tkinter.

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

## 🔐 Features

### Security
- **Encrypted Storage**: All OTP secrets are encrypted using NaCl (Argon2 + XSalsa20-Poly1305)
- **Password Protected**: Vault is locked with user-defined password (minimum 4 characters)
- **Memory Safety**: Sensitive data is automatically cleared from memory
- **Automatic Backups**: Creates timestamped backups before saving (keeps last 5)

### OTP Management
- **Add OTP Entries**: Via QR code scanning or manual URI input
- **Generate Codes**: Real-time OTP code generation with batch updates
- **Export/Import**: JSON export/import for backup and migration
- **QR Code Display**: Show QR codes for any entry to scan on other devices
- **Delete Entries**: Safe deletion with confirmation dialog

### User Interface
- **Search**: Fast search across entry names and URIs
- **Sorting**: Sort by name or creation date (ascending/descending)
- **Lazy Loading**: Efficient handling of large entry lists (50 entries per batch)
- **Clipboard Copy**: One-click copy with auto-clear after 30 seconds
- **Responsive Design**: Scrollable interface with mouse wheel support

## 📋 Requirements

- Python 3.8 or higher
- Operating System: Windows, Linux, or macOS

## 🚀 Installation

### 1. Clone or Download

```bash
git clone https://github.com/yourusername/thaotp.git
cd thaotp
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

**Dependencies:**
- `pillow>=11.3.0` - Image processing
- `PyNaCl>=1.5.0` - Cryptography
- `opencv-python~=4.12.0.88` - QR code reading
- `pyotp~=2.9.0` - OTP generation
- `qrcode~=8.0` - QR code generation

### 3. Run the Application

```bash
python main.py
```

## 📖 Usage

### First Time Setup

1. Launch the application
2. Since no password is set, the vault starts unlocked
3. Click **"Add OTP URL"** to add your first entry
4. Click **"Change Password"** to set a password for encryption

### Adding OTP Entries

**Method 1: QR Code Scan**
1. Click **"Add OTP URL"**
2. Click **"Browse..."** to select a QR code image
3. Click **"Read QR Code"** to extract the URI
4. Click **"Add OTP Entry"**

**Method 2: Manual Entry**
1. Click **"Add OTP URL"**
2. Paste the OTP URI in the "OTP URL" field
   - Format: `otpauth://totp/Name:user@example.com?secret=...&issuer=Name`
3. Click **"Add OTP Entry"**

### Using OTP Codes

- **Copy Code**: Click 📋 button to copy code to clipboard (auto-clears in 30s)
- **Show QR Code**: Click 🔲 button to display QR code for the entry
- **Codes Update**: All codes refresh automatically every 30 seconds

### Search and Sort

- **Search**: Type in the search box to filter entries by name or URI
- **Sort**: Use the dropdown to sort by:
  - Name ↑ / Name ↓
  - Date ↑ / Date ↓

### Export and Import

**Export:**
1. Click **"Export JSON"**
2. Choose save location
3. JSON file contains all entries (unencrypted!)

**Import:**
1. Click **"Import JSON"**
2. Select JSON file
3. Duplicates are automatically skipped

### QR Code Features

**Display QR Code:**
1. Click 🔲 button next to any entry
2. Scan with your authenticator app
3. Optionally save as PNG or copy URI

**⚠️ Security Warning:** QR codes contain your secret keys. Store them securely!

### Password Management

**Change Password:**
1. Click **"Change Password"**
2. Enter new password twice
3. Confirm change

**⚠️ Important:** If you forget your password, your data cannot be recovered!

## 📁 File Structure

```
thaotp/
├── main.py              # Main application window
├── otp_class.py         # OTP vault logic
├── extra_windows.py     # Dialog windows
├── config_manager.py    # Configuration storage
├── crypt_utils.py       # Encryption utilities
├── qr_generator.py      # QR code generation
├── service.py           # QR code reading
├── exceptions.py        # Custom exceptions
├── requirements.txt     # Dependencies
└── README.md           # This file
```

## 💾 Data Storage

### Configuration Location

**Windows:**
```
%LOCALAPPDATA%\ThaOTP\config.json
```

**Linux/Mac:**
```
~/.config/ThaOTP/config.json
```

### Backup Files

Automatic backups are created before each save:
```
config.json.backup_20241117_143052
```

Only the 5 most recent backups are kept.

### Data Format

- **Encrypted**: OTP secrets are encrypted in `config.json`
- **Exported**: JSON exports are **unencrypted** - store securely!

## 🔒 Security Best Practices

1. **Use Strong Passwords**: Minimum 4 characters (recommended: 12+)
2. **Backup Regularly**: Export your entries to a secure location
3. **Secure QR Codes**: Don't share QR code screenshots
4. **Lock When Away**: Close the application when not in use
5. **Verify URIs**: Only add OTP URIs from trusted sources

## 🐛 Troubleshooting

### QR Code Features Not Available

**Error:** `QR Code generation not available`

**Solution:**
```bash
pip install qrcode[pil]
```

### Cannot Read QR Code

**Error:** `Im Bild wurde kein QR-Code gefunden`

**Possible causes:**
- Image quality too low
- QR code is damaged
- Wrong file format

**Solutions:**
- Use high-resolution images
- Ensure QR code is clearly visible
- Try PNG format

### Wrong Password Error

**Error:** `Entschlüsselung fehlgeschlagen`

**Solution:**
- Check for typos
- Remember: passwords are case-sensitive
- If forgotten, data cannot be recovered

### Import Fails

**Error:** `Could not import: ...`

**Solutions:**
- Check JSON file format
- Ensure file is not corrupted
- Verify file contains valid OTP URIs

## 🔧 Advanced Configuration

### Changing Lazy Load Batch Size

Edit `main.py`:
```python
LAZY_LOAD_BATCH_SIZE = 50  # Change to desired number
```

### Changing Clipboard Auto-Clear Time

Edit `main.py`:
```python
CLIPBOARD_CLEAR_DELAY_MS = 30000  # Time in milliseconds
```

### Changing Maximum Backups

Edit `otp_class.py`:
```python
MAX_BACKUP_FILES = 5  # Number of backups to keep
```

## 📝 Development

### Project Structure

- **Model**: `otp_class.py` - Core OTP management logic
- **View**: `main.py`, `extra_windows.py` - GUI components
- **Controller**: Event handlers in `main.py`
- **Utils**: `crypt_utils.py`, `config_manager.py`, `service.py`

### Adding Logging

Enable debug logging:
```python
logging.basicConfig(level=logging.DEBUG)
```

### Running Tests

Test individual modules:
```bash
python config_manager.py
python crypt_utils.py
python qr_generator.py
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

Copyright [2025] [ecki]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## ⚠️ Disclaimer

This software is provided "as is", without warranty of any kind. The authors are not responsible for any data loss or security breaches. Always keep backups of your OTP secrets in a secure location.

## 🆘 Support

For issues, questions, or feature requests:

- Create an issue on GitHub
- Check existing documentation
- Review troubleshooting section

## 📊 Version History

### v1.0.0 (Current)
- Initial release
- Encrypted OTP storage
- QR code support
- Search and sort functionality
- Import/Export features
- Lazy loading for large lists
- Clipboard auto-clear
- Automatic backups

## 👏 Acknowledgments

- **PyOTP**: OTP implementation
- **PyNaCl**: Cryptography library
- **qrcode**: QR code generation
- **OpenCV**: QR code reading
- **Pillow**: Image processing

---

**Made with ❤️ for secure OTP management**