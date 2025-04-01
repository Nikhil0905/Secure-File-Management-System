import os
import json
import logging
import hashlib
import bcrypt
import jwt
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import sys
import ctypes
from ctypes import wintypes

class SecureFileManager:
    def __init__(self, storage_dir: str = "secure_storage"):
        self.storage_dir = self._normalize_path(storage_dir)
        self.users_file = self.storage_dir / "users.json"
        self.files_file = self.storage_dir / "files.json"
        self.key_file = self.storage_dir / "encryption.key"
        self.session_file = self.storage_dir / "session.json"
        self.setup_logging()
        self.setup_storage()
        self.fernet = self._load_or_create_key()
        self.current_user = None
        self.token = None
        self._load_session()

    def _normalize_path(self, path: str) -> Path:
        """Convert path to Windows format and resolve to absolute path"""
        try:
            # Convert to Path object and resolve to absolute path
            path_obj = Path(path).resolve()
            # Convert to Windows format (backslashes)
            return Path(str(path_obj).replace('/', '\\'))
        except Exception as e:
            logging.error(f"Error normalizing path {path}: {str(e)}")
            raise ValueError(f"Invalid path: {path}")

    def _validate_file_access(self, file_path: Path) -> Tuple[bool, str]:
        """Validate file access permissions and existence"""
        try:
            # Check if file exists
            if not file_path.exists():
                return False, f"File not found: {file_path}"

            # Check if file is accessible
            try:
                with open(file_path, 'rb') as f:
                    # Try to read first byte
                    f.seek(0)
                    f.read(1)
                    f.seek(0)
                return True, ""
            except PermissionError:
                return False, f"Permission denied: {file_path}"
            except Exception as e:
                return False, f"Error accessing file: {str(e)}"
        except Exception as e:
            return False, f"Error validating file: {str(e)}"

    def _get_file_size(self, file_path: Path) -> int:
        """Get file size with proper Windows handling"""
        try:
            return file_path.stat().st_size
        except Exception as e:
            logging.error(f"Error getting file size for {file_path}: {str(e)}")
            raise ValueError(f"Error getting file size: {str(e)}")

    def _check_disk_space(self, required_space: int) -> Tuple[bool, str]:
        """Check if enough disk space is available"""
        try:
            free_bytes = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                ctypes.c_wchar_p(str(self.storage_dir)),
                None,
                None,
                ctypes.pointer(free_bytes)
            )
            if free_bytes.value < required_space:
                return False, f"Insufficient disk space. Required: {required_space} bytes, Available: {free_bytes.value} bytes"
            return True, ""
        except Exception as e:
            logging.error(f"Error checking disk space: {str(e)}")
            return False, f"Error checking disk space: {str(e)}"

    def setup_logging(self):
        try:
            self.storage_dir.mkdir(exist_ok=True)
            logging.basicConfig(
                filename=self.storage_dir / "system.log",
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s'
            )
        except PermissionError:
            print("Error: No permission to create storage directory or log file.")
            sys.exit(1)
        except Exception as e:
            print(f"Error setting up logging: {str(e)}")
            sys.exit(1)

    def setup_storage(self):
        try:
            self.storage_dir.mkdir(exist_ok=True)
            if not self.users_file.exists():
                self._save_json(self.users_file, {})
            if not self.files_file.exists():
                self._save_json(self.files_file, {})
        except PermissionError:
            print("Error: No permission to create or access storage files.")
            sys.exit(1)
        except Exception as e:
            print(f"Error setting up storage: {str(e)}")
            sys.exit(1)

    def _load_or_create_key(self) -> Fernet:
        try:
            if self.key_file.exists():
                with open(self.key_file, 'rb') as f:
                    return Fernet(f.read())
            else:
                key = Fernet.generate_key()
                with open(self.key_file, 'wb') as f:
                    f.write(key)
                return Fernet(key)
        except PermissionError:
            print("Error: No permission to access encryption key file.")
            sys.exit(1)
        except Exception as e:
            print(f"Error loading or creating encryption key: {str(e)}")
            sys.exit(1)

    def _save_json(self, file_path: Path, data: dict):
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=4)
        except PermissionError:
            print(f"Error: No permission to write to {file_path}")
            sys.exit(1)
        except Exception as e:
            print(f"Error saving JSON file: {str(e)}")
            sys.exit(1)

    def _load_json(self, file_path: Path) -> dict:
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except PermissionError:
            print(f"Error: No permission to read {file_path}")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in {file_path}")
            return {}
        except Exception as e:
            print(f"Error loading JSON file: {str(e)}")
            return {}

    def _load_session(self):
        """Load session information from file"""
        try:
            if self.session_file.exists():
                session_data = self._load_json(self.session_file)
                if session_data:
                    self.current_user = session_data.get('current_user')
                    self.token = session_data.get('token')
                    if self.current_user and self.token:
                        if not self.verify_token(self.token):
                            self.logout()
        except Exception as e:
            logging.error(f"Error loading session: {str(e)}")
            self.logout()

    def _save_session(self):
        """Save session information to file"""
        try:
            session_data = {
                'current_user': self.current_user,
                'token': self.token
            }
            self._save_json(self.session_file, session_data)
        except Exception as e:
            logging.error(f"Error saving session: {str(e)}")

    def register_user(self, username: str, password: str) -> bool:
        users = self._load_json(self.users_file)
        if username in users:
            return False
        
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        users[username] = {
            'password': hashed.decode(),
            'salt': salt.decode(),
            'created_at': datetime.now().isoformat()
        }
        self._save_json(self.users_file, users)
        logging.info(f"New user registered: {username}")
        return True

    def login(self, username: str, password: str) -> bool:
        users = self._load_json(self.users_file)
        if username not in users:
            return False

        user_data = users[username]
        if bcrypt.checkpw(password.encode(), user_data['password'].encode()):
            self.current_user = username
            self.token = self._generate_token(username)
            self._save_session()
            logging.info(f"User logged in: {username}")
            return True
        return False

    def _generate_token(self, username: str) -> str:
        payload = {
            'username': username,
            'exp': datetime.utcnow() + timedelta(days=1)
        }
        return jwt.encode(payload, self.key_file.read_bytes(), algorithm='HS256')

    def verify_token(self, token: str) -> bool:
        try:
            payload = jwt.decode(token, self.key_file.read_bytes(), algorithms=['HS256'])
            self.current_user = payload['username']
            return True
        except jwt.ExpiredSignatureError:
            return False
        except jwt.InvalidTokenError:
            return False

    def upload_file(self, file_path: str) -> bool:
        if not self.current_user:
            return False

        try:
            # Normalize and validate the file path
            normalized_path = self._normalize_path(file_path)
            is_valid, error_msg = self._validate_file_access(normalized_path)
            if not is_valid:
                logging.error(error_msg)
                return False

            # Check file size
            file_size = self._get_file_size(normalized_path)
            if file_size > 100 * 1024 * 1024:  # 100MB limit
                logging.error(f"File too large: {normalized_path}")
                return False

            # Read file data
            with open(normalized_path, 'rb') as f:
                file_data = f.read()
            
            # Calculate SHA-256 hash
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # Encrypt file data
            encrypted_data = self.fernet.encrypt(file_data)
            
            # Check available disk space (with 10% buffer)
            required_space = len(encrypted_data) * 1.1
            has_space, space_error = self._check_disk_space(required_space)
            if not has_space:
                logging.error(space_error)
                return False

            # Save encrypted file
            filename = normalized_path.name
            encrypted_path = self.storage_dir / f"{file_hash}_{filename}"
            
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)

            # Update files database
            files = self._load_json(self.files_file)
            files[filename] = {
                'hash': file_hash,
                'encrypted_path': str(encrypted_path),
                'owner': self.current_user,
                'uploaded_at': datetime.now().isoformat(),
                'size': file_size
            }
            self._save_json(self.files_file, files)
            
            logging.info(f"File uploaded: {filename} by {self.current_user}")
            return True
        except Exception as e:
            logging.error(f"Error uploading file: {str(e)}")
            return False

    def download_file(self, filename: str) -> Optional[bytes]:
        if not self.current_user:
            return None

        files = self._load_json(self.files_file)
        if filename not in files:
            logging.error(f"File not found: {filename}")
            return None

        file_info = files[filename]
        # Check if user owns the file or has been shared with them
        if file_info['owner'] != self.current_user and self.current_user not in file_info.get('shared_with', []):
            logging.error(f"Access denied: {filename}")
            return None

        try:
            encrypted_path = self._normalize_path(file_info['encrypted_path'])
            if not encrypted_path.exists():
                logging.error(f"Encrypted file not found: {encrypted_path}")
                return None

            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.fernet.decrypt(encrypted_data)
            
            # Verify file integrity
            if hashlib.sha256(decrypted_data).hexdigest() != file_info['hash']:
                logging.error(f"File integrity check failed for: {filename}")
                return None

            logging.info(f"File downloaded: {filename} by {self.current_user}")
            return decrypted_data
        except Exception as e:
            logging.error(f"Error downloading file: {str(e)}")
            return None

    def list_files(self) -> List[Dict]:
        if not self.current_user:
            return []

        files = self._load_json(self.files_file)
        user_files = []
        for filename, info in files.items():
            # Include files owned by the user or shared with them
            if info['owner'] == self.current_user or self.current_user in info.get('shared_with', []):
                user_files.append({
                    'name': filename,
                    'size': info.get('size', 0),
                    'uploaded_at': info.get('uploaded_at', ''),
                    'owner': info['owner'],
                    'shared': self.current_user != info['owner']
                })
        return user_files

    def delete_file(self, filename: str) -> bool:
        if not self.current_user:
            return False

        files = self._load_json(self.files_file)
        if filename not in files or files[filename]['owner'] != self.current_user:
            logging.error(f"File not found or access denied: {filename}")
            return False

        try:
            encrypted_path = files[filename]['encrypted_path']
            if os.path.exists(encrypted_path):
                os.remove(encrypted_path)
            
            # Remove from files database
            del files[filename]
            self._save_json(self.files_file, files)
            
            logging.info(f"File deleted: {filename} by {self.current_user}")
            return True
        except Exception as e:
            logging.error(f"Error deleting file: {str(e)}")
            return False

    def logout(self):
        """Logout the current user and clear session"""
        if self.current_user:
            logging.info(f"User logged out: {self.current_user}")
        self.current_user = None
        self.token = None
        try:
            if self.session_file.exists():
                os.remove(self.session_file)
        except Exception as e:
            logging.error(f"Error removing session file: {str(e)}")

    def share_file(self, filename: str, username: str) -> bool:
        if not self.current_user:
            return False

        files = self._load_json(self.files_file)
        if filename not in files:
            logging.error(f"File not found: {filename}")
            return False

        file_info = files[filename]
        if file_info['owner'] != self.current_user:
            logging.error(f"Access denied: {filename}")
            return False

        # Check if user exists
        users = self._load_json(self.users_file)
        if username not in users:
            logging.error(f"User not found: {username}")
            return False

        # Initialize shared_with list if it doesn't exist
        if 'shared_with' not in file_info:
            file_info['shared_with'] = []

        # Add user to shared_with list if not already present
        if username not in file_info['shared_with']:
            file_info['shared_with'].append(username)
            self._save_json(self.files_file, files)
            logging.info(f"File {filename} shared with {username} by {self.current_user}")
            return True

        return False

    def revoke_share(self, filename: str, username: str) -> bool:
        if not self.current_user:
            return False

        files = self._load_json(self.files_file)
        if filename not in files:
            logging.error(f"File not found: {filename}")
            return False

        file_info = files[filename]
        if file_info['owner'] != self.current_user:
            logging.error(f"Access denied: {filename}")
            return False

        # Check if file is shared with the user
        if 'shared_with' not in file_info or username not in file_info['shared_with']:
            logging.error(f"File {filename} is not shared with {username}")
            return False

        # Remove user from shared_with list
        file_info['shared_with'].remove(username)
        self._save_json(self.files_file, files)
        logging.info(f"File sharing revoked for {filename} from {username} by {self.current_user}")
        return True 