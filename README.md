# Project Kagami — A Secure Password Manager

**Kagami** (鏡), meaning "mirror", is a secure, local password manager designed with clarity and strength in mind. It provides a simple GUI built in Tkinter and ensures your data is safe using strong cryptographic methods.

---

## 🛡 Features

- Master password protection (created on first launch)
- AES-GCM encryption of stored passwords
- Argon2 key derivation from master password
- Encrypted vault file (`vault.dat`)
- Hashed master password file (`master.hash`)
- GUI built with Tkinter
- Generate strong passwords
- Show saved passwords by selecting a service from dropdown
- Add/edit/delete service-password entries

---

## 🔐 Security Principles

- Master password is hashed (with Argon2) and never stored in plaintext
- Password vault is encrypted entirely with AES-GCM (256-bit)
- Decryption key is derived from the master password via Argon2
- No decrypted data is saved to disk
- Vault automatically re-encrypts after changes

---

## 📂 File Structure

