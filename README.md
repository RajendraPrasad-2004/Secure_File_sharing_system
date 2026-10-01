# 🔐 Secure File Sharing System

A secure web-based file sharing system designed to allow users to upload, store, and share files while protecting sensitive data through authentication, encryption, and controlled access.

## 📌 Overview

The **Secure File Sharing System** provides a secure platform for exchanging files between authorized users. The system focuses on maintaining the **confidentiality, integrity, and availability** of shared files.

Users can securely upload files, manage their files, and share them with authorized users. Security mechanisms are implemented to prevent unauthorized access and protect files during storage and transfer.

## 🎯 Objectives

* Provide secure file upload and download.
* Authenticate users before accessing the system.
* Protect files using encryption.
* Control who can access shared files.
* Prevent unauthorized file access.
* Maintain file integrity during storage and transfer.
* Provide a simple and user-friendly interface.

## ✨ Features

* 🔑 User Registration and Login
* 📁 Secure File Upload
* 📥 Secure File Download
* 🔐 File Encryption
* 👥 Controlled File Sharing
* 🛡️ Authentication and Authorization
* 🗑️ File Management
* 📋 Access Control
* 🔎 File Information and Metadata
* 🚫 Unauthorized Access Prevention

## 🏗️ System Architecture

```text
              ┌─────────────────┐
              │      User       │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │   Web Interface │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Authentication  │
              │ & Authorization │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Backend Server  │
              └───────┬─────────┘
                      │
             ┌────────┴─────────┐
             ▼                  ▼
      ┌──────────────┐   ┌──────────────┐
      │ Encryption   │   │   Database   │
      │ Module       │   │              │
      └──────┬───────┘   └──────────────┘
             │
             ▼
      ┌──────────────┐
      │ Secure File  │
      │   Storage    │
      └──────────────┘
```

## 🔒 Security Mechanisms

### Authentication

Users must log in using valid credentials before accessing protected resources.

### Authorization

The system verifies whether a user has permission to access a particular file.

### Encryption

Files are encrypted before being stored so that unauthorized users cannot directly read the stored data.

### Secure File Sharing

Files can be shared only with authorized users according to the access permissions configured by the owner.

### Integrity Protection

File integrity can be verified using cryptographic hashing mechanisms.

## 🛠️ Technologies Used

* HTML
* CSS
* JavaScript
* Node.js
* Express.js
* MongoDB
* Cryptography
* Git
* GitHub

## 📂 Project Structure

```text
Secure-File-Sharing-System/
│
├── frontend/
│   ├── index.html
│   ├── login.html
│   ├── dashboard.html
│   ├── css/
│   └── js/
│
├── backend/
│   ├── routes/
│   ├── controllers/
│   ├── models/
│   ├── middleware/
│   ├── uploads/
│   └── server.js
│
├── .gitignore
└── README.md
```

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/USERNAME/secure-file-sharing-system.git
```

### 2. Navigate to the project

```bash
cd secure-file-sharing-system
```

### 3. Install dependencies

```bash
npm install
```

### 4. Configure Environment Variables

Create a `.env` file:

```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_secret_key
```

**Do not upload the `.env` file to GitHub.**

### 5. Start the server

```bash
npm start
```

The application will run locally on:

```text
http://localhost:5000
```

## 🔄 Working Flow

```text
User Registration/Login
          ↓
Authentication
          ↓
User Dashboard
          ↓
Select File
          ↓
File Encryption
          ↓
Secure Storage
          ↓
Share With Authorized User
          ↓
Access Verification
          ↓
File Decryption
          ↓
Secure Download
```

## 🧪 Testing

The system can be tested using the following scenarios:

* Valid user login
* Invalid login attempt
* File upload
* File encryption
* File download
* Unauthorized file access
* File sharing with another user
* Access denied for non-authorized users
* File integrity verification

## 🔮 Future Enhancements

* Two-factor authentication (2FA)
* Password reset through email
* Role-based access control
* File expiration links
* Audit logs
* Cloud storage integration
* Advanced malware/file scanning
* Multi-device support

## 👨‍💻 Author

**Rajendra Prasad**

B.E. Information Science and Engineering

## 📄 License

This project is developed for **academic and educational purposes** as part of an Information and Network Security project.
