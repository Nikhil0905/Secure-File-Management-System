import os
import json
import logging
import hashlib
import bcrypt
import jwt
import pyotp
import qrcode
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import sys
import base64
import re
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import random

# Load environment variables
load_dotenv()

console = Console()

class SecureFileManager:
    def __init__(self):
        """Initialize the secure file manager"""
        # Load environment variables
        load_dotenv()
        
        # Initialize configuration with robust error handling
        try:
            # Get and clean MAX_FILE_SIZE value
            max_size_str = os.getenv('MAX_FILE_SIZE', '104857600')
            # Remove any comments and whitespace
            max_size_str = max_size_str.split('#')[0].strip()
            self.max_file_size = int(max_size_str)
            
            # Get and clean other environment variables
            self.storage_dir = os.getenv('STORAGE_DIR', 'secure_storage').strip()
            self.allowed_file_types = [t.strip() for t in os.getenv('ALLOWED_FILE_TYPES', '*').strip().split(',')]
            self.jwt_secret = os.getenv('JWT_SECRET_KEY', 'your-super-secret-key-here').strip()
            
            # Initialize paths
            self.base_dir = os.path.abspath(os.path.dirname(__file__))
            self.storage_path = os.path.join(self.base_dir, self.storage_dir)
            self.users_file = os.path.join(self.storage_path, 'users.json')
            self.files_file = os.path.join(self.storage_path, 'files.json')
            
            # Initialize state
            self.current_user = None
            self.current_token = None
            
            # Setup logging
            self.setup_logging()
            
            # Setup storage
            self.setup_storage()
            
            # Setup malware rules
            self._setup_malware_rules()
            
            # Load existing session
            self._load_session()
            
        except ValueError as e:
            logging.error(f"Invalid environment variable value: {str(e)}")
            raise ValueError(f"Invalid environment variable value: {str(e)}")
        except Exception as e:
            logging.error(f"Error initializing SecureFileManager: {str(e)}")
            raise

    def setup_logging(self):
        """Setup logging configuration"""
        try:
            # Create storage directory if it doesn't exist
            os.makedirs(self.storage_path, exist_ok=True)
            
            # Setup logging
            log_level = os.getenv('LOG_LEVEL', 'INFO')
            logging.basicConfig(
                filename=os.path.join(self.storage_path, "system.log"),
                level=getattr(logging, log_level),
                format='%(asctime)s - %(levelname)s - %(message)s'
            )
        except Exception as e:
            print(f"Error setting up logging: {e}")
            sys.exit(1)

    def setup_storage(self):
        """Setup storage directories and files"""
        try:
            # Create storage directory if it doesn't exist
            os.makedirs(self.storage_path, exist_ok=True)
            
            # Create JSON files if they don't exist
            if not os.path.exists(self.users_file):
                self._save_json(self.users_file, {})
            if not os.path.exists(self.files_file):
                self._save_json(self.files_file, {})
        except Exception as e:
            logging.error(f"Error setting up storage: {e}")
            sys.exit(1)

    def _setup_malware_rules(self):
        """Setup basic malware detection patterns"""
        self.suspicious_patterns = [
            # Executable patterns
            rb'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF',  # Windows PE header
            rb'ELF\x02\x01\x01',  # Linux ELF header
            
            # Common malware signatures
            rb'CreateRemoteThread',  # Process injection
            rb'VirtualAlloc',        # Memory allocation
            rb'WriteProcessMemory',  # Process memory writing
            rb'ShellExecute',        # Shell execution
            rb'WScript.Shell',       # WScript shell
            rb'cmd.exe /c',          # Command execution
            rb'powershell -enc',     # Encoded PowerShell
            rb'certutil -decode',    # Certificate utility abuse
            rb'bitsadmin',          # BITS admin abuse
            rb'regsvr32 /s',        # DLL registration abuse
            
            # Ransomware indicators
            rb'encrypt',            # Encryption keywords
            rb'decrypt',            # Decryption keywords
            rb'ransom',             # Ransomware keywords
            rb'bitcoin',            # Cryptocurrency keywords
            rb'wallet',             # Wallet keywords
            
            # Malicious script patterns
            rb'<script>eval(',      # JavaScript eval
            rb'<script>document.cookie',  # Cookie theft
            rb'<script>XMLHttpRequest',   # XHR requests
            rb'<script>localStorage',     # Local storage access
            rb'<script>sessionStorage',   # Session storage access
        ]

    def _load_or_create_key(self) -> Fernet:
        """Load or create encryption key"""
        try:
            if os.path.exists(os.path.join(self.storage_path, 'encryption.key')):
                with open(os.path.join(self.storage_path, 'encryption.key'), 'rb') as f:
                    return Fernet(f.read())
            else:
                # Generate a stronger key using PBKDF2
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=os.urandom(16),
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(os.urandom(32)))
                with open(os.path.join(self.storage_path, 'encryption.key'), 'wb') as f:
                    f.write(key)
                return Fernet(key)
        except Exception as e:
            logging.error(f"Error loading or creating encryption key: {e}")
            sys.exit(1)

    def _save_json(self, file_path: str, data: dict):
        """Save JSON data to file"""
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving JSON file: {e}")
            raise

    def _load_json(self, file_path: str) -> dict:
        """Load JSON data from file"""
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading JSON file: {e}")
            return {}

    def _load_session(self):
        """Load session information from file"""
        try:
            session_file = os.path.join(self.storage_path, 'session.json')
            if os.path.exists(session_file):
                session_data = self._load_json(session_file)
                if session_data:
                    self.current_user = session_data.get('current_user')
                    self.current_token = session_data.get('token')
                    if self.current_user and self.current_token:
                        # Only verify token expiration, don't auto-logout
                        try:
                            payload = jwt.decode(self.current_token, self.jwt_secret, algorithms=['HS256'])
                            exp = datetime.fromisoformat(payload['exp'])
                            if datetime.utcnow() > exp:
                                # Only log warning, don't auto-logout
                                logging.warning(f"Token expired for user: {self.current_user}")
                                return
                        except jwt.ExpiredSignatureError:
                            # Only log warning, don't auto-logout
                            logging.warning("Token expired")
                            return
                        except Exception as e:
                            logging.error(f"Error verifying token: {str(e)}")
                            return
                        
                        # Log successful session load
                        logging.info(f"Session loaded for user: {self.current_user}")
                    else:
                        logging.warning("Invalid session data")
            else:
                logging.info("No session file found")
        except Exception as e:
            logging.error(f"Error loading session: {str(e)}")
            # Don't auto-logout on error, just log it

    def _save_session(self):
        """Save session information to file"""
        try:
            session_file = os.path.join(self.storage_path, 'session.json')
            if self.current_user and self.current_token:
                session_data = {
                    'current_user': self.current_user,
                    'token': self.current_token,
                    'last_updated': datetime.now().isoformat()
                }
                self._save_json(session_file, session_data)
                logging.info(f"Session saved for user: {self.current_user}")
            else:
                # If no valid session, remove session file
                if os.path.exists(session_file):
                    os.remove(session_file)
        except Exception as e:
            logging.error(f"Error saving session: {str(e)}")

    def register_user(self, username: str, password: str) -> bool:
        """Register a new user with mandatory 2FA"""
        try:
            users = self._load_json(self.users_file)
            
            if username in users:
                return False
            
            # Generate 2FA secret
            secret = pyotp.random_base32()
            
            # Create QR code for 2FA
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(username, issuer_name="SecureFileManager")
            
            # Create QR code for terminal display
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            
            # Save QR code
            qr_path = os.path.join(self.storage_path, f"{username}_2fa.png")
            qr_img.save(qr_path)
            
            # Generate backup code
            backup_code = ''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=8))
            
            # Hash password and store user data
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            users[username] = {
                'password': hashed_password,
                '2fa_secret': secret,
                '2fa_backup_code': backup_code,
                '2fa_enabled': True  # Always enabled
            }
            
            self._save_json(self.users_file, users)
            
            # Display QR code and instructions in terminal
            print("\n" + "="*50)
            print("2FA Setup Required for", username)
            print("="*50)
            print("\n1. Scan this QR code with your authenticator app (e.g., Google Authenticator):")
            print("\n")
            # Display QR code in terminal
            qr.print_ascii(invert=True)
            print("\n")
            print("2. Enter the 6-digit code from your authenticator app when logging in")
            print("\n3. Save this backup code in case you lose access to your authenticator:")
            print(f"   {backup_code}")
            print("\n" + "="*50)
            
            return True
        except Exception as e:
            logging.error(f"Error registering user: {e}")
            return False

    def login(self, username: str, password: str) -> bool:
        """Login with 2FA"""
        try:
            users = self._load_json(self.users_file)
            
            if username not in users:
                return False
            
            user_data = users[username]
            
            # Verify password
            if not bcrypt.checkpw(password.encode(), user_data['password'].encode()):
                return False
            
            # Check if 2FA is enabled
            if user_data.get('2fa_enabled', False):
                # Get 2FA code from user
                totp = pyotp.TOTP(user_data['2fa_secret'])
                print("\n2FA Verification Required")
                print("Please enter the 6-digit code from your authenticator app")
                print("Or enter your backup code if you've lost access to your authenticator")
                code = input("Enter code: ").strip()
                
                # Check if it's a backup code
                if code == user_data.get('2fa_backup_code'):
                    print("Backup code used. Please set up 2FA again.")
                    # Disable 2FA and generate new backup code
                    user_data['2fa_enabled'] = False
                    user_data['2fa_backup_code'] = ''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=8))
                    self._save_json(self.users_file, users)
                    return False
                
                # Verify 2FA code
                if not totp.verify(code):
                    return False
            
            # Login successful
            self.current_user = username
            self.current_token = self._generate_token(username)
            
            # Save session immediately
            self._save_session()
            
            # Verify session was saved
            if not os.path.exists(os.path.join(self.storage_path, 'session.json')):
                logging.error("Session file was not created")
                return False
                
            logging.info(f"User logged in: {username}")
            return True
            
        except Exception as e:
            logging.error(f"Error during login: {e}")
            return False

    def _generate_token(self, username: str) -> str:
        """Generate JWT token with enhanced security"""
        try:
            # Generate a unique token ID
            token_id = os.urandom(16).hex()
            
            # Create token payload
            payload = {
                'username': username,
                'token_id': token_id,
                'created_at': datetime.utcnow().isoformat(),
                'exp': datetime.utcnow() + timedelta(hours=24)  # Token expires in 24 hours
            }
            
            # Generate token with enhanced security
            token = jwt.encode(payload, self.jwt_secret, algorithm='HS256')
            
            # Log token generation
            logging.info(f"Token generated for user: {username}")
            
            return token
        except Exception as e:
            logging.error(f"Error generating token: {str(e)}")
            raise

    def verify_token(self, token: str) -> bool:
        """Verify JWT token with enhanced security"""
        try:
            # Decode and verify token
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            
            # Check if token is expired
            exp = datetime.fromisoformat(payload['exp'])
            if datetime.utcnow() > exp:
                logging.warning(f"Token expired for user: {payload['username']}")
                return False
            
            # Verify user exists
            users = self._load_json(self.users_file)
            if payload['username'] not in users:
                logging.warning(f"Token user not found: {payload['username']}")
                return False
            
            # Update current user
            self.current_user = payload['username']
            
            # Log successful verification
            logging.info(f"Token verified for user: {self.current_user}")
            
            return True
        except jwt.ExpiredSignatureError:
            logging.warning("Token expired")
            return False
        except jwt.InvalidTokenError as e:
            logging.warning(f"Invalid token: {str(e)}")
            return False
        except Exception as e:
            logging.error(f"Error verifying token: {str(e)}")
            return False

    def _get_file_extension(self, file_path: str) -> str:
        """Get file extension from path"""
        return os.path.splitext(file_path)[1].lower().lstrip('.')

    def scan_file(self, file_path: str) -> Tuple[bool, str]:
        """Scan file for malware and validate file type"""
        try:
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                logging.warning(f"File too large: {file_path}")
                return False, "File exceeds maximum size limit"

            # Only check for obvious malware patterns
            with open(file_path, 'rb') as f:
                content = f.read()
                # Only check first 1MB of file for performance
                content_to_scan = content[:1024*1024]
                
                # Only check for obvious malware patterns
                dangerous_patterns = [
                    rb'CreateRemoteThread',  # Process injection
                    rb'WriteProcessMemory',  # Process memory writing
                    rb'cmd.exe /c',          # Command execution
                    rb'powershell -enc',     # Encoded PowerShell
                ]
                
                # Count dangerous patterns
                dangerous_count = 0
                for pattern in dangerous_patterns:
                    if pattern in content_to_scan:
                        dangerous_count += 1
                
                # Only reject if multiple dangerous patterns are found
                if dangerous_count >= 2:
                    logging.warning(f"Dangerous patterns found in: {file_path}")
                    return False, "Dangerous patterns detected"

            return True, "File is safe"
        except Exception as e:
            logging.error(f"Error scanning file: {str(e)}")
            return False, f"Error scanning file: {str(e)}"

    def upload_file(self, file_path: str) -> Tuple[bool, str]:
        """Upload a file"""
        if not self.current_user:
            return False, "Not authenticated"

        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return False, "File not found"

            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Scan file for malware
            is_clean, scan_result = self.scan_file(file_path)
            if not is_clean:
                return False, f"File rejected: {scan_result}"

            # Calculate SHA-256 hash
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # Encrypt file data
            encrypted_data = self._load_or_create_key().encrypt(file_data)
            
            # Save encrypted file
            filename = file_path.name
            encrypted_path = os.path.join(self.storage_path, f"{file_hash}_{filename}")
            
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)

            # Update files database
            files = self._load_json(self.files_file)
            files[filename] = {
                'hash': file_hash,
                'encrypted_path': encrypted_path,
                'owner': self.current_user,
                'uploaded_at': datetime.now().isoformat(),
                'size': len(file_data),
                'shared_with': []
            }
            self._save_json(self.files_file, files)
            
            logging.info(f"File uploaded: {filename} by {self.current_user}")
            return True, "File uploaded successfully"
        except Exception as e:
            logging.error(f"Error uploading file: {e}")
            return False, str(e)

    def download_file(self, filename: str, save_path: str) -> bool:
        """Download a file from secure storage"""
        try:
            if not self.current_user:
                return False
                
            # Get file info
            file_info = self._load_json(self.files_file).get(filename)
            if not file_info:
                return False
                
            # Check permissions
            if file_info['owner'] != self.current_user and self.current_user not in file_info.get('shared_with', []):
                return False
                
            # Get encrypted file path
            encrypted_path = Path(file_info['encrypted_path'])
            if not encrypted_path.exists():
                return False
                
            # Create save directory if it doesn't exist
            save_dir = Path(save_path).parent
            save_dir.mkdir(parents=True, exist_ok=True)
            
            # Decrypt and save file
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
                
            decrypted_data = self._load_or_create_key().decrypt(encrypted_data)
            
            with open(save_path, 'wb') as f:
                f.write(decrypted_data)
                
            return True
            
        except Exception as e:
            logging.error(f"Error downloading file: {str(e)}")
            return False

    def list_files(self) -> List[Dict]:
        """List all files with detailed information"""
        if not self.current_user:
            return []

        try:
            files = self._load_json(self.files_file)
            file_list = []
            
            for filename, info in files.items():
                if info['owner'] == self.current_user or self.current_user in info.get('shared_with', []):
                    # Format file size
                    size_bytes = int(info['size'])  # Ensure size is an integer
                    if size_bytes < 1024:
                        size_str = f"{size_bytes} B"
                    elif size_bytes < 1024*1024:
                        size_str = f"{size_bytes/1024:.2f} KB"
                    elif size_bytes < 1024*1024*1024:
                        size_str = f"{size_bytes/(1024*1024):.2f} MB"
                    else:
                        size_str = f"{size_bytes/(1024*1024*1024):.2f} GB"
                    
                    # Format upload date
                    upload_date = datetime.fromisoformat(info['uploaded_at'])
                    date_str = upload_date.strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Get file extension
                    file_ext = os.path.splitext(filename)[1].lower()
                    
                    # Determine file type
                    if file_ext in ['.txt', '.md', '.py', '.js', '.html', '.css', '.json', '.xml']:
                        file_type = "Text"
                    elif file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
                        file_type = "Image"
                    elif file_ext in ['.pdf']:
                        file_type = "PDF"
                    elif file_ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
                        file_type = "Office"
                    elif file_ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
                        file_type = "Archive"
                    elif file_ext in ['.mp3', '.wav', '.ogg', '.flac']:
                        file_type = "Audio"
                    elif file_ext in ['.mp4', '.avi', '.mov', '.wmv']:
                        file_type = "Video"
                    else:
                        file_type = "Other"
                    
                    file_info = {
                        'name': filename,
                        'size': size_str,
                        'size_bytes': size_bytes,
                        'uploaded_at': upload_date,  # Store as datetime object
                        'uploaded_at_str': date_str,  # Store formatted string
                        'file_type': file_type,
                        'extension': file_ext,
                        'owner': info['owner'],
                        'shared_with': info.get('shared_with', []),
                        'hash': info['hash'],
                        'is_owner': info['owner'] == self.current_user
                    }
                    file_list.append(file_info)
            
            # Sort files by upload date (newest first)
            file_list.sort(key=lambda x: x['uploaded_at'], reverse=True)
            
            # Convert datetime objects to strings for display
            for file_info in file_list:
                file_info['uploaded_at'] = file_info['uploaded_at_str']
                del file_info['uploaded_at_str']
            
            return file_list
        except Exception as e:
            logging.error(f"Error listing files: {e}")
            return []

    def share_file(self, filename: str, target_user: str) -> bool:
        """Share a file with another user"""
        try:
            if not self.current_user:
                logging.error("No user logged in")
                return False
            
            files = self._load_json(self.files_file)
            users = self._load_json(self.users_file)
            
            # Check if target user exists
            if target_user not in users:
                logging.error(f"Target user {target_user} does not exist")
                return False
            
            # Check if file exists and belongs to current user
            if filename not in files:
                logging.error(f"File {filename} not found")
                return False
            
            file_info = files[filename]
            if file_info['owner'] != self.current_user:
                logging.error(f"File {filename} does not belong to current user")
                return False
            
            # Add target user to shared_with list if not already there
            if 'shared_with' not in file_info:
                file_info['shared_with'] = []
            
            if target_user not in file_info['shared_with']:
                file_info['shared_with'].append(target_user)
                self._save_json(self.files_file, files)
                logging.info(f"File {filename} shared with {target_user}")
                return True
            
            logging.info(f"File {filename} already shared with {target_user}")
            return True
            
        except Exception as e:
            logging.error(f"Error sharing file: {e}")
            return False

    def delete_file(self, filename: str) -> bool:
        """Delete a file"""
        if not self.current_user:
            return False

        try:
            files = self._load_json(self.files_file)
            if filename not in files:
                return False

            file_info = files[filename]
            if file_info['owner'] != self.current_user:
                return False

            # Delete encrypted file
            try:
                os.remove(file_info['encrypted_path'])
            except Exception as e:
                logging.error(f"Error deleting encrypted file: {e}")

            # Remove from files database
            del files[filename]
            self._save_json(self.files_file, files)
            
            logging.info(f"File deleted: {filename} by {self.current_user}")
            return True
        except Exception as e:
            logging.error(f"Error deleting file: {e}")
            return False

    def logout(self):
        """Logout current user with enhanced security"""
        try:
            if self.current_user:
                logging.info(f"User logging out: {self.current_user}")
            
            # Clear session data
            self.current_user = None
            self.current_token = None
            
            # Remove session file
            session_file = os.path.join(self.storage_path, 'session.json')
            if os.path.exists(session_file):
                os.remove(session_file)
            
            # Log successful logout
            logging.info("Logout completed successfully")
        except Exception as e:
            logging.error(f"Error during logout: {str(e)}")

    def setup_2fa(self, username):
        """Set up 2FA for a user"""
        try:
            # Generate a secret key
            secret = pyotp.random_base32()
            
            # Create TOTP object
            totp = pyotp.TOTP(secret)
            
            # Generate QR code
            provisioning_uri = totp.provisioning_uri(
                username,
                issuer_name="Secure File Manager"
            )
            
            # Create QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            # Generate backup code
            backup_code = base64.b32encode(os.urandom(5)).decode('utf-8')
            self._save_backup_code(username, backup_code)
            
            # Save 2FA secret to user data
            self._save_2fa_secret(username, secret)
            
            # Display QR code and backup code
            console.print("\n[bold green]Scan this QR code with your authenticator app:[/bold green]")
            # Print QR code directly to terminal
            qr.print_ascii(invert=True)
            console.print(f"\n[yellow]Backup code (save this securely): {backup_code}[/yellow]\n")
            
            return True
        except Exception as e:
            logging.error(f"Error setting up 2FA: {str(e)}")
            return False

    def verify_2fa(self, username: str, code: str) -> bool:
        """Verify 2FA code"""
        try:
            users = self._load_json(self.users_file)
            if username not in users:
                return False
            
            user_data = users[username]
            if not user_data.get('2fa_enabled', False):
                return False
            
            # Check if it's a backup code
            if code == user_data.get('2fa_backup_code'):
                print("Backup code used. Please set up 2FA again.")
                # Disable 2FA and generate new backup code
                user_data['2fa_enabled'] = False
                user_data['2fa_backup_code'] = ''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=8))
                self._save_json(self.users_file, users)
                return False
            
            # Verify 2FA code
            totp = pyotp.TOTP(user_data['2fa_secret'])
            return totp.verify(code)
        except Exception as e:
            logging.error(f"Error verifying 2FA: {e}")
            return False

    def _save_2fa_secret(self, username, secret):
        """Save 2FA secret for a user"""
        try:
            users = self._load_json(self.users_file)
            if username in users:
                users[username]['2fa_secret'] = secret
                self._save_json(self.users_file, users)
                return True
            return False
        except Exception as e:
            logging.error(f"Error saving 2FA secret: {str(e)}")
            return False

    def _get_2fa_secret(self, username):
        """Get 2FA secret for a user"""
        try:
            users = self._load_json(self.users_file)
            return users.get(username, {}).get('2fa_secret')
        except Exception as e:
            logging.error(f"Error getting 2FA secret: {str(e)}")
            return None

    def _save_backup_code(self, username, backup_code):
        """Save backup code for a user"""
        try:
            users = self._load_json(self.users_file)
            if username in users:
                users[username]['backup_code'] = backup_code
                self._save_json(self.users_file, users)
                return True
            return False
        except Exception as e:
            logging.error(f"Error saving backup code: {str(e)}")
            return False

    def _get_backup_code(self, username):
        """Get backup code for a user"""
        try:
            users = self._load_json(self.users_file)
            return users.get(username, {}).get('backup_code')
        except Exception as e:
            logging.error(f"Error getting backup code: {str(e)}")
            return None

    def _save_users(self, users):
        """Save users data to file"""
        try:
            self._save_json(self.users_file, users)
        except Exception as e:
            logging.error(f"Error saving users data: {e}")
            raise

    def _load_users(self):
        """Load users data from file"""
        try:
            return self._load_json(self.users_file)
        except Exception as e:
            logging.error(f"Error loading users data: {e}")
            return {}

    def verify_password(self, username: str, password: str) -> bool:
        """Verify user password"""
        try:
            users = self._load_json(self.users_file)
            if username not in users:
                return False
            
            user_data = users[username]
            return bcrypt.checkpw(password.encode(), user_data['password'].encode())
        except Exception as e:
            logging.error(f"Error verifying password: {e}")
            return False

    def is_2fa_enabled(self, username: str) -> bool:
        """Check if 2FA is enabled for a user"""
        try:
            users = self._load_json(self.users_file)
            return users.get(username, {}).get('2fa_enabled', False)
        except Exception as e:
            logging.error(f"Error checking 2FA status: {e}")
            return False

    def complete_login(self, username: str):
        """Complete the login process"""
        try:
            self.current_user = username
            self.current_token = self._generate_token(username)
            self._save_session()
            logging.info(f"User logged in: {username}")
        except Exception as e:
            logging.error(f"Error completing login: {e}")
            raise

    def is_logged_in(self) -> bool:
        """Check if a user is currently logged in"""
        return self.current_user is not None 
