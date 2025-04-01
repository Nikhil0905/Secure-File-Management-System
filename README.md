# Secure File Management System (SFMS)

A CLI-based secure file management system that provides encrypted storage and secure access to files.

## Features

- User Authentication (JWT-based)
- File Encryption (AES-256)
- File Integrity Verification (SHA-256)
- Secure File Storage
- Logging and Access Control
- CLI Interface for User Interaction
- Windows-Compatible Path Handling
- Secure File Sharing Between Users

## Requirements

- Python 3.x installed on your system
- Windows OS (since we're using Windows-specific code)
- Sufficient disk space (at least 1GB free space recommended)
- Administrator privileges (for some operations)

## Installation

1. Clone or download the repository to your PC
2. Navigate to the project directory:
   ```bash
   cd "path/to/project"
   ```
3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Configure storage location in `.env` file:
   ```
   STORAGE_DIR=D:/secure_storage  # Change D: to your preferred drive
   ```

## Project Structure

```
Secure File Management System/
├── README.md           # This file
├── requirements.txt    # Python dependencies
├── .env               # Configuration file
├── main.py            # Main CLI interface
├── secure_file_manager.py  # Core functionality
└── secure_storage/    # Created automatically
```

## Usage

### Basic Commands

1. **Register a new user**:
   ```bash
   python main.py register username --password
   ```

2. **Login to the system**:
   ```bash
   python main.py login username
   # Enter password when prompted
   ```

3. **Check login status**:
   ```bash
   python main.py status
   ```

4. **Upload a file**:
   ```bash
   python main.py upload "path/to/your/file"
   # Supports both relative and absolute paths
   # Handles spaces and special characters in paths
   ```

5. **List all files**:
   ```bash
   python main.py list
   # Shows files with serial numbers, ownership, and sharing status
   ```

6. **Download a file**:
   ```bash
   python main.py download filename "output/path"
   # Creates output directory if it doesn't exist
   ```

7. **Delete a file**:
   ```bash
   python main.py delete filename
   ```

8. **Share a file with another user**:
   ```bash
   python main.py share filename username
   ```

9. **Revoke file sharing**:
   ```bash
   python main.py revoke filename username
   ```

10. **Logout from the system**:
    ```bash
    python main.py logout
    ```

### Important Notes

- Maximum file size: 100MB
- All files are automatically encrypted
- Files are stored in the specified secure_storage directory
- Logs are stored in secure_storage/system.log
- Session information is stored in secure_storage/session.json
- Supports Windows path formats (both forward and backward slashes)
- Handles spaces and special characters in file paths
- Automatically creates necessary directories for downloads

## Security Features

- All files are encrypted using AES-256 encryption
- Passwords are hashed using bcrypt
- JWT tokens for authentication
- File integrity verification using SHA-256
- Access control and logging
- Secure storage of sensitive data
- Secure file sharing between users
- Permission-based access control

## Path Handling Features

1. **Windows Compatibility**
   - Supports both forward (/) and backward (\) slashes
   - Automatically converts paths to Windows format
   - Handles UNC paths and network shares

2. **Path Validation**
   - Validates file existence
   - Checks file permissions
   - Resolves relative paths to absolute paths
   - Handles spaces and special characters

3. **Error Handling**
   - Clear error messages for invalid paths
   - Permission error handling
   - Disk space verification
   - Directory creation for downloads

## Troubleshooting Guide

### Common Issues and Solutions

1. **"Insufficient disk space" Error**
   - Check available disk space
   - Clear unnecessary files
   - Change storage location in .env file
   - Make sure you have at least 1GB free space

2. **"File not found" Error**
   - Make sure you're logged in
   - Check if the file exists
   - Use correct file path
   - Use quotes around paths with spaces
   - Try using absolute path instead of relative path

3. **Permission Errors**
   - Run as administrator
   - Check folder permissions
   - Make sure storage directory is accessible
   - Set proper permissions using PowerShell:
     ```powershell
     $acl = Get-Acl "path/to/directory"
     $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("YourUsername","FullControl","Allow")
     $acl.SetAccessRule($rule)
     Set-Acl "path/to/directory" $acl
     ```

4. **Login Issues**
   - Check if you're already logged in
   - Try logging out and logging in again
   - Check session.json file
   - Clear secure_storage directory if needed

5. **Path-Related Issues**
   - Use quotes around paths with spaces
   - Use absolute paths if relative paths don't work
   - Check if the path exists and is accessible
   - Make sure you have proper permissions

### Checking Logs

To check system logs:
```bash
type secure_storage\system.log
```

## Best Practices

1. **File Management**
   - Keep file names simple and avoid special characters
   - Use descriptive names for files
   - Regularly clean up unnecessary files
   - Use quotes around paths with spaces

2. **Security**
   - Use strong passwords
   - Logout when not using the system
   - Don't share your login credentials
   - Keep your encryption key safe
   - Be careful when sharing files

3. **Storage**
   - Monitor disk space
   - Use appropriate storage location
   - Backup important files
   - Use absolute paths for critical operations

4. **Path Handling**
   - Use quotes for paths with spaces
   - Use absolute paths for important operations
   - Check path permissions before operations
   - Verify disk space before large operations

## Example Session

```bash
# Register a new user
python main.py register john --password

# Login
python main.py login john
# Enter password when prompted

# Upload a file (with spaces in path)
python main.py upload "My Documents/report.pdf"

# List files
python main.py list

# Share with another user
python main.py share report.pdf alice

# Download the file (with spaces in output path)
python main.py download report.pdf "Downloads/My Files/report.pdf"

# Delete the file
python main.py delete report.pdf

# Logout
python main.py logout
```

## Support

If you encounter any issues:
1. Check the logs in secure_storage/system.log
2. Verify all requirements are met
3. Ensure proper permissions are set
4. Check available disk space
5. Verify file paths are correct
6. Try using absolute paths
7. Check file sharing permissions

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Environment Variables

The system uses environment variables to manage configuration settings. These are stored in the `.env` file in the project root directory.

### Available Environment Variables

1. **STORAGE_DIR**
   - Purpose: Specifies the directory where encrypted files are stored
   - Format: `STORAGE_DIR=D:/secure_storage`
   - Default: If not set, uses `secure_storage` in the project directory
   - Example: `STORAGE_DIR=D:/my_secure_files`

2. **JWT_SECRET**
   - Purpose: Secret key for JWT token generation and verification
   - Format: `JWT_SECRET=your_secret_key`
   - Default: If not set, system generates a random key
   - Note: Keep this secret and secure

3. **MAX_FILE_SIZE**
   - Purpose: Maximum allowed file size in bytes
   - Format: `MAX_FILE_SIZE=104857600` (100MB in bytes)
   - Default: 100MB if not specified

### How to Use Environment Variables

1. **Create/Edit .env file**:
   ```bash
   # Create a new .env file
   echo STORAGE_DIR=D:/secure_storage > .env
   echo JWT_SECRET=your_secret_key >> .env
   echo MAX_FILE_SIZE=104857600 >> .env
   ```

2. **Change Storage Location**:
   - Edit the `.env` file
   - Change `STORAGE_DIR` to your preferred location
   - Make sure the directory exists and has proper permissions
   - Use absolute paths for better reliability

3. **Security Considerations**:
   - Never commit `.env` file to version control
   - Keep your JWT_SECRET secure
   - Use absolute paths for STORAGE_DIR
   - Ensure the storage directory has proper permissions

4. **Verification**:
   - The system will create the storage directory if it doesn't exist
   - Check logs for any environment-related issues
   - Use `python main.py status` to verify configuration

### Example .env File

```
# Storage Configuration
STORAGE_DIR=D:/secure_storage

# Security
JWT_SECRET=your_secure_secret_key_here

# System Limits
MAX_FILE_SIZE=104857600
``` 