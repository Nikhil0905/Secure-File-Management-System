# Secure File Management System

A secure file management system with encryption, 2FA, and malware scanning capabilities.

## Features

- 🔒 AES-256 encryption for all files
- 🔐 Two-Factor Authentication (2FA)
- 🛡️ Malware scanning
- 📁 File sharing capabilities
- 📊 Detailed file information with serial numbering
- 🔑 Secure session management
- 📝 Comprehensive logging

## Prerequisites

- Python 3.8 or higher
- Windows 10/11 (for setup.bat)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Nikhil0905/Secure-File-Management-System
cd secure-file-management-system
```

2. Run the setup script:
```bash
setup.bat
```

This will:
- Create a virtual environment
- Install required packages
- Set up the storage directory
- Configure environment variables

## Usage

### Basic Commands

1. Register a new user:
```bash
python main.py register <username>
```

2. Login (2FA required):
```bash
python main.py login <username>
```

3. Check login status:
```bash
python main.py status
```

4. Upload a file:
```bash
python main.py upload "path\to\your\file"
```

5. List files (with serial numbering):
```bash
python main.py list
```
Output example:
```
┌──────┬──────────────────┬──────────┬────────┬──────────────┬────────┬──────────┐
│ S.No │ Name             │ Size     │ Type   │ Uploaded    │ Owner  │ Shared   │
├──────┼──────────────────┼──────────┼────────┼──────────────┼────────┼──────────┤
│ 1    │ file1.pdf        │ 1.2 MB   │ PDF    │ 2024-03-20  │ Admin  │ No       │
│ 2    │ file2.docx       │ 2.5 MB   │ DOCX   │ 2024-03-21  │ Admin  │ John     │
└──────┴──────────────────┴──────────┴────────┴──────────────┴────────┴──────────┘
```

6. Download a file:
```bash
python main.py download "filename" "path\to\save\location"
```

7. Share a file:
```bash
python main.py share "filename" "other_username"
```

8. Delete a file:
```bash
python main.py delete "filename"
```

9. Logout:
```bash
python main.py logout
```

### Security Features

1. **Two-Factor Authentication (2FA)**
   - Required for all users
   - Uses authenticator apps (e.g., Google Authenticator)
   - Backup codes provided for account recovery
   - QR code displayed in terminal for easy setup

2. **File Encryption**
   - AES-256 encryption for all stored files
   - Secure key management
   - Automatic encryption/decryption

3. **Malware Protection**
   - Basic malware scanning
   - File size limits
   - Suspicious pattern detection

4. **Session Security**
   - JWT-based authentication
   - 24-hour session expiration
   - Secure session storage
   - Manual logout required

## Configuration

The system can be configured through the `.env` file:

```env
# Storage Configuration
STORAGE_DIR=secure_storage
MAX_FILE_SIZE=104857600

# Security Configuration
JWT_SECRET_KEY=your-super-secret-key-here

# Logging Configuration
LOG_LEVEL=INFO

# File Type Configuration
ALLOWED_FILE_TYPES=*
```

## Directory Structure

```
secure-file-management-system/
├── .env                    # Configuration file
├── .gitignore             # Git ignore rules
├── main.py                # Main application entry point
├── secure_file_manager.py # Core functionality
├── requirements.txt       # Python dependencies
├── setup.bat             # Windows setup script
├── README.md             # Documentation
└── secure_storage/       # Encrypted file storage
    ├── users.json        # User data
    ├── files.json        # File metadata
    └── system.log        # System logs
```

## Security Considerations

1. Always keep your 2FA backup codes secure
2. Regularly change your password
3. Don't share your JWT secret key
4. Monitor the system logs for suspicious activity
5. Use the logout command when finished

## Error Handling

The system includes comprehensive error handling:
- Invalid credentials
- File size limits
- Malware detection
- Session expiration
- Network issues
- File sharing permissions

## Logging

System logs are stored in `secure_storage/system.log` and include:
- User authentication attempts
- File operations
- Security events
- System errors
- Session management

## Support

For issues or questions, please:
1. Check the system logs
2. Verify your configuration
3. Ensure all dependencies are installed
4. Contact system administrator 
