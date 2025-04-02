# Technical Documentation - Secure File Management System

## System Architecture

### Core Components

1. **SecureFileManager Class**
   - Main class handling all file operations
   - Implements AES-256 encryption
   - Manages user authentication and 2FA
   - Handles file sharing and permissions

2. **CLI Interface (main.py)**
   - Command-line interface using Click
   - Rich terminal output formatting
   - Error handling and user feedback

3. **Storage System**
   - JSON-based metadata storage
   - Encrypted file storage
   - Session management

## Implementation Details

### 1. Authentication System

#### JWT Implementation
```python
def _generate_token(self, username: str) -> str:
    payload = {
        'username': username,
        'token_id': os.urandom(16).hex(),
        'created_at': datetime.utcnow().isoformat(),
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
```

#### 2FA Implementation
```python
def verify_2fa(self, username: str, code: str) -> bool:
    totp = pyotp.TOTP(user_data['2fa_secret'])
    return totp.verify(code)
```

### 2. File Management

#### File Upload Process
1. File validation
2. Malware scanning
3. Encryption
4. Metadata storage
5. File storage

#### File Download Process
1. Permission verification
2. File retrieval
3. Decryption
4. Integrity check

### 3. Security Features

#### Encryption
- Algorithm: AES-256
- Key Management: Secure key storage
- Implementation: cryptography library

#### Malware Scanning
- Pattern-based detection
- File size limits
- Content analysis

### 4. Session Management

#### Session Storage
```python
session_data = {
    'current_user': username,
    'token': token,
    'last_updated': datetime.now().isoformat()
}
```

#### Session Validation
- Token expiration check
- User existence verification
- Permission validation

## Data Structures

### 1. User Data (users.json)
```json
{
    "username": {
        "password": "hashed_password",
        "2fa_secret": "secret_key",
        "2fa_backup_code": "backup_code",
        "2fa_enabled": true
    }
}
```

### 2. File Data (files.json)
```json
{
    "filename": {
        "owner": "username",
        "size": 1234567,
        "file_type": "pdf",
        "uploaded_at": "2024-03-21T10:00:00",
        "shared_with": ["user1", "user2"]
    }
}
```

## Error Handling

### 1. Authentication Errors
- Invalid credentials
- Expired tokens
- 2FA verification failures

### 2. File Operation Errors
- File not found
- Permission denied
- Size limits exceeded
- Malware detected

### 3. System Errors
- Storage issues
- Encryption/decryption failures
- JSON parsing errors

## Logging System

### Log Levels
- INFO: Normal operations
- WARNING: Potential issues
- ERROR: Operation failures
- DEBUG: Detailed debugging

### Log Format
```
[2024-03-21 10:00:00] INFO: User logged in: username
[2024-03-21 10:01:00] WARNING: File size limit exceeded
[2024-03-21 10:02:00] ERROR: Encryption failed
```

## Performance Considerations

### 1. File Operations
- Chunked file processing
- Memory-efficient encryption
- Asynchronous operations where possible

### 2. Storage Optimization
- Efficient JSON storage
- File deduplication
- Cleanup of temporary files

## Security Measures

### 1. Password Security
- bcrypt hashing
- Salt generation
- Minimum length requirements

### 2. File Security
- AES-256 encryption
- Secure key storage
- File integrity verification

### 3. Session Security
- JWT tokens
- 24-hour expiration
- Secure storage

## Dependencies

### Core Dependencies
- click: CLI interface
- python-dotenv: Environment management
- bcrypt: Password hashing
- PyJWT: Token management
- pyotp: 2FA implementation
- qrcode: QR code generation
- cryptography: Encryption
- rich: Terminal formatting

### Version Requirements
- Python >= 3.8
- Windows 10/11 (for setup.bat)

## Testing

### Unit Tests
- Authentication tests
- File operation tests
- Security feature tests

### Integration Tests
- End-to-end workflows
- Error handling scenarios
- Performance benchmarks

## Deployment

### Requirements
1. Python environment
2. Required packages
3. Storage directory
4. Environment variables

### Setup Process
1. Run setup.bat
2. Configure .env
3. Initialize storage
4. Test functionality

## Maintenance

### Regular Tasks
1. Log rotation
2. Storage cleanup
3. Security updates
4. Performance monitoring

### Backup Procedures
1. User data backup
2. File metadata backup
3. Configuration backup
4. Log backup 
