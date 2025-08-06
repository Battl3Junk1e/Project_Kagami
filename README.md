# Project Kagami — A Secure Password Manager

**Kagami** (鏡), meaning "mirror", is a minimalist, open-source password manager for desktop that reflects your commitment to clarity and security.

Project Kagami provides a simple, intuitive GUI built with [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) and uses strong modern cryptography to keep your data safe.  
Your credentials are **encrypted locally** and all sensitive files are stored securely in system-specific, hidden user folders — never on your desktop or in obvious locations.

---

## Features

- 🔑 **Strong encryption** using scrypt KDF and AES-GCM
- 💾 **Data is saved in hidden system folders**
    - Windows: `%LOCALAPPDATA%\ProjectKagami\`
    - macOS: `~/Library/Application Support/ProjectKagami/`
    - Linux: `~/.projectkagami/`
- 👀 **Minimal interface**—no visible file clutter
- 🚀 **No bloat:** only necessary code and libraries, for fast, compact `.exe`
- 🗝️ **Custom file extension** (`.kagami`) for data and key files
- 📋 One-click copy and delete for entries
- 🔒 Master password never leaves your device

---

## How it Works

1. On first launch, Kagami prompts you to create a master password.
2. Credentials and encryption keys are stored in a secure, app-specific folder (see above).
3. Your data files:
    - `passwords.kagami` – encrypted credentials
    - `master.kagami` – your encrypted key
4. All encryption and decryption happen **locally**.

---

## Installation & Running

**Windows:**

1. Download or build `kagami.exe`
2. Double-click to run

**macOS/Linux:**

1. Run with Python 3.9+  
   `python kagami.py`

---

## Packaging as an EXE (Advanced)

- Use [PyInstaller](https://pyinstaller.org/) or [Nuitka](https://nuitka.net/) for packaging.
- All imports are strictly minimized for a smaller executable.
- Example:
    ```
    pyinstaller --clean --onefile --noconsole --icon=kagami_icon_standard.ico --add-data "kagami_icon_standard.ico;." --add-data "logo.webp;." kagami.py
    ```

---

## Dependencies

- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter)
- [Pillow](https://python-pillow.org/) (PIL)
- [cryptography](https://cryptography.io/)

Install them with:
```bash
pip install customtkinter pillow cryptography


