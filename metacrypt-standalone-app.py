#!/usr/bin/env python3
"""
MetaCrypt - Encrypted Metadata Embedding System
Complete Standalone GUI Application

This is a single-file application containing all components.
Just run: python metacrypt_gui.py

Requirements:
- Python 3.9+
- Dependencies listed at bottom of file
"""

import os
import sys
import struct
import zlib
import base64
import tempfile
from typing import Optional, Tuple

# Cryptography imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from argon2.low_level import Type, hash_secret_raw

# GUI imports
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QFileDialog,
    QMessageBox, QProgressBar, QGroupBox, QTabWidget, QComboBox,
    QCheckBox, QSpinBox, QFrame
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QIcon, QPalette, QColor

# Image handling
from PIL import Image


# ============================================================================
# CRYPTOGRAPHY ENGINE
# ============================================================================

class CryptoEngine:
    """
    AES-256-GCM encryption with Argon2id key derivation.
    
    DESIGN RATIONALE:
    - AES-256-GCM: Authenticated encryption (confidentiality + integrity)
    - Argon2id: Memory-hard KDF resistant to GPU/ASIC attacks
    - Random nonces: Unique per encryption (catastrophic if reused with GCM)
    - Salt: Unique per password derivation (prevents rainbow tables)
    """
    
    TIME_COST = 3
    MEMORY_COST = 65536  # 64 MB
    PARALLELISM = 4
    HASH_LEN = 32  # 256 bits for AES-256
    SALT_SIZE = 16  # 128 bits
    NONCE_SIZE = 12  # 96 bits (GCM standard)
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive 256-bit key from password using Argon2id"""
        password_bytes = password.encode('utf-8')
        
        key = hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=CryptoEngine.TIME_COST,
            memory_cost=CryptoEngine.MEMORY_COST,
            parallelism=CryptoEngine.PARALLELISM,
            hash_len=CryptoEngine.HASH_LEN,
            type=Type.ID
        )
        
        return key
    
    @staticmethod
    def encrypt(plaintext: bytes, password: str) -> bytes:
        """
        Encrypt data with AES-256-GCM.
        Returns: salt || nonce || (ciphertext + auth_tag)
        """
        salt = os.urandom(CryptoEngine.SALT_SIZE)
        nonce = os.urandom(CryptoEngine.NONCE_SIZE)
        
        key = CryptoEngine.derive_key(password, salt)
        
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        return salt + nonce + ciphertext
    
    @staticmethod
    def decrypt(encrypted_payload: bytes, password: str) -> bytes:
        """Decrypt AES-256-GCM encrypted data"""
        min_size = CryptoEngine.SALT_SIZE + CryptoEngine.NONCE_SIZE + 16
        if len(encrypted_payload) < min_size:
            raise ValueError("Invalid encrypted payload")
        
        salt = encrypted_payload[:CryptoEngine.SALT_SIZE]
        nonce = encrypted_payload[CryptoEngine.SALT_SIZE:CryptoEngine.SALT_SIZE + CryptoEngine.NONCE_SIZE]
        ciphertext = encrypted_payload[CryptoEngine.SALT_SIZE + CryptoEngine.NONCE_SIZE:]
        
        key = CryptoEngine.derive_key(password, salt)
        
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return plaintext


# ============================================================================
# METADATA HANDLERS
# ============================================================================

class PNGHandler:
    """
    PNG metadata handler using tEXt chunks.
    Standard: PNG Specification 1.2 (W3C)
    """
    
    PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
    
    @staticmethod
    def validate(file_path: str) -> bool:
        try:
            with open(file_path, 'rb') as f:
                return f.read(8) == PNGHandler.PNG_SIGNATURE
        except:
            return False
    
    @staticmethod
    def embed(input_path: str, data: bytes, output_path: str) -> None:
        if not PNGHandler.validate(input_path):
            raise ValueError("Not a valid PNG file")
        
        # Encode as base64 for text chunk
        encoded_data = base64.b64encode(data).decode('ascii')
        
        # Create tEXt chunk: keyword\0text
        keyword = b'MetaCrypt'
        text = encoded_data.encode('latin-1')
        chunk_data = keyword + b'\x00' + text
        
        # Build chunk
        chunk_type = b'tEXt'
        chunk_length = struct.pack('>I', len(chunk_data))
        chunk_crc = struct.pack('>I', zlib.crc32(chunk_type + chunk_data) & 0xffffffff)
        chunk = chunk_length + chunk_type + chunk_data + chunk_crc
        
        # Read original PNG
        with open(input_path, 'rb') as f:
            png_data = f.read()
        
        # Find IEND and insert before it
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos == -1:
            raise ValueError("Invalid PNG: IEND not found")
        
        iend_chunk_start = iend_pos - 4
        output_data = png_data[:iend_chunk_start] + chunk + png_data[iend_chunk_start:]
        
        with open(output_path, 'wb') as f:
            f.write(output_data)
    
    @staticmethod
    def extract(input_path: str) -> Optional[bytes]:
        if not PNGHandler.validate(input_path):
            raise ValueError("Not a valid PNG file")
        
        with open(input_path, 'rb') as f:
            f.seek(8)
            
            while True:
                length_bytes = f.read(4)
                if len(length_bytes) < 4:
                    break
                
                chunk_length = struct.unpack('>I', length_bytes)[0]
                chunk_type = f.read(4)
                
                if not chunk_type:
                    break
                
                chunk_data = f.read(chunk_length)
                chunk_crc = f.read(4)
                
                if chunk_type == b'tEXt':
                    null_pos = chunk_data.find(b'\x00')
                    if null_pos != -1:
                        keyword = chunk_data[:null_pos].decode('latin-1')
                        if keyword == 'MetaCrypt':
                            text = chunk_data[null_pos + 1:].decode('latin-1')
                            try:
                                return base64.b64decode(text)
                            except:
                                return None
                
                if chunk_type == b'IEND':
                    break
        
        return None


class JPEGHandler:
    """
    JPEG metadata handler using COM (comment) markers.
    Standard: JPEG/JFIF (ITU T.81)
    """
    
    SOI = b'\xff\xd8'
    COM = b'\xff\xfe'
    
    @staticmethod
    def validate(file_path: str) -> bool:
        try:
            with open(file_path, 'rb') as f:
                return f.read(2) == JPEGHandler.SOI
        except:
            return False
    
    @staticmethod
    def embed(input_path: str, data: bytes, output_path: str) -> None:
        if not JPEGHandler.validate(input_path):
            raise ValueError("Not a valid JPEG file")
        
        encoded_data = base64.b64encode(data).decode('ascii')
        comment_text = f"METACRYPT:{encoded_data}"
        comment_bytes = comment_text.encode('utf-8')
        
        if len(comment_bytes) > 65533:
            raise ValueError(f"Data too large: {len(comment_bytes)} bytes")
        
        length = len(comment_bytes) + 2
        com_segment = JPEGHandler.COM + struct.pack('>H', length) + comment_bytes
        
        with open(input_path, 'rb') as f:
            jpeg_data = f.read()
        
        output_data = jpeg_data[:2] + com_segment + jpeg_data[2:]
        
        with open(output_path, 'wb') as f:
            f.write(output_data)
    
    @staticmethod
    def extract(input_path: str) -> Optional[bytes]:
        if not JPEGHandler.validate(input_path):
            raise ValueError("Not a valid JPEG file")
        
        with open(input_path, 'rb') as f:
            f.seek(2)
            
            while True:
                marker_bytes = f.read(2)
                if len(marker_bytes) < 2:
                    break
                
                marker = marker_bytes[0]
                marker_type = marker_bytes[1]
                
                if marker != 0xFF:
                    break
                
                if marker_type == 0xD9:
                    break
                
                if marker_type == 0xD8 or (0xD0 <= marker_type <= 0xD7):
                    continue
                
                length_bytes = f.read(2)
                if len(length_bytes) < 2:
                    break
                
                length = struct.unpack('>H', length_bytes)[0]
                data_length = length - 2
                
                if data_length > 0:
                    segment_data = f.read(data_length)
                    
                    if marker_type == 0xFE:  # COM
                        try:
                            text = segment_data.decode('utf-8')
                            if text.startswith('METACRYPT:'):
                                encoded = text[10:]  # Skip "METACRYPT:"
                                return base64.b64decode(encoded)
                        except:
                            pass
        
        return None


class PDFHandler:
    """PDF metadata handler using info dictionary"""
    
    @staticmethod
    def validate(file_path: str) -> bool:
        try:
            with open(file_path, 'rb') as f:
                return f.read(5) == b'%PDF-'
        except:
            return False
    
    @staticmethod
    def embed(input_path: str, data: bytes, output_path: str) -> None:
        try:
            from PyPDF2 import PdfReader, PdfWriter
        except ImportError:
            raise RuntimeError("PyPDF2 not installed. Run: pip install PyPDF2")
        
        if not PDFHandler.validate(input_path):
            raise ValueError("Not a valid PDF file")
        
        encoded_data = base64.b64encode(data).decode('ascii')
        
        reader = PdfReader(input_path)
        writer = PdfWriter()
        
        for page in reader.pages:
            writer.add_page(page)
        
        writer.add_metadata({'/MetaCrypt': encoded_data})
        
        if reader.metadata:
            writer.add_metadata(dict(reader.metadata))
        
        with open(output_path, 'wb') as f:
            writer.write(f)
    
    @staticmethod
    def extract(input_path: str) -> Optional[bytes]:
        try:
            from PyPDF2 import PdfReader
        except ImportError:
            raise RuntimeError("PyPDF2 not installed")
        
        if not PDFHandler.validate(input_path):
            raise ValueError("Not a valid PDF file")
        
        reader = PdfReader(input_path)
        if not reader.metadata:
            return None
        
        if '/MetaCrypt' in reader.metadata:
            encoded_data = reader.metadata['/MetaCrypt']
            try:
                return base64.b64decode(encoded_data)
            except:
                return None
        
        return None


class MP3Handler:
    """MP3 metadata handler using ID3v2 tags"""
    
    @staticmethod
    def validate(file_path: str) -> bool:
        try:
            from mutagen.mp3 import MP3
            MP3(file_path)
            return True
        except:
            return False
    
    @staticmethod
    def embed(input_path: str, data: bytes, output_path: str) -> None:
        try:
            from mutagen.id3 import ID3, TXXX
            import shutil
        except ImportError:
            raise RuntimeError("mutagen not installed. Run: pip install mutagen")
        
        if not MP3Handler.validate(input_path):
            raise ValueError("Not a valid MP3 file")
        
        encoded_data = base64.b64encode(data).decode('ascii')
        
        if input_path != output_path:
            import shutil
            shutil.copy2(input_path, output_path)
        
        try:
            tags = ID3(output_path)
        except:
            tags = ID3()
        
        tags.add(TXXX(encoding=3, desc='MetaCrypt', text=encoded_data))
        tags.save(output_path, v2_version=4)
    
    @staticmethod
    def extract(input_path: str) -> Optional[bytes]:
        try:
            from mutagen.id3 import ID3
        except ImportError:
            raise RuntimeError("mutagen not installed")
        
        if not MP3Handler.validate(input_path):
            raise ValueError("Not a valid MP3 file")
        
        try:
            tags = ID3(input_path)
            
            for frame in tags.getall('TXXX'):
                if frame.desc == 'MetaCrypt':
                    encoded_data = frame.text[0]
                    try:
                        return base64.b64decode(encoded_data)
                    except:
                        return None
        except:
            pass
        
        return None


class MP4Handler:
    """MP4 metadata handler using custom atoms"""
    
    @staticmethod
    def validate(file_path: str) -> bool:
        try:
            from mutagen.mp4 import MP4
            MP4(file_path)
            return True
        except:
            return False
    
    @staticmethod
    def embed(input_path: str, data: bytes, output_path: str) -> None:
        try:
            from mutagen.mp4 import MP4
            import shutil
        except ImportError:
            raise RuntimeError("mutagen not installed. Run: pip install mutagen")
        
        if not MP4Handler.validate(input_path):
            raise ValueError("Not a valid MP4 file")
        
        encoded_data = base64.b64encode(data).decode('ascii')
        
        if input_path != output_path:
            shutil.copy2(input_path, output_path)
        
        audio = MP4(output_path)
        audio['----:com.metacrypt:data'] = encoded_data.encode('utf-8')
        audio.save()
    
    @staticmethod
    def extract(input_path: str) -> Optional[bytes]:
        try:
            from mutagen.mp4 import MP4
        except ImportError:
            raise RuntimeError("mutagen not installed")
        
        if not MP4Handler.validate(input_path):
            raise ValueError("Not a valid MP4 file")
        
        try:
            audio = MP4(input_path)
            key = '----:com.metacrypt:data'
            
            if key in audio:
                encoded_data = audio[key][0].decode('utf-8')
                try:
                    return base64.b64decode(encoded_data)
                except:
                    return None
        except:
            pass
        
        return None


def get_handler(file_path: str):
    """Get appropriate handler for file type"""
    ext = os.path.splitext(file_path)[1].lower()
    
    handlers = {
        '.png': PNGHandler,
        '.jpg': JPEGHandler,
        '.jpeg': JPEGHandler,
        '.pdf': PDFHandler,
        '.mp3': MP3Handler,
        '.mp4': MP4Handler,
        '.m4a': MP4Handler,
    }
    
    return handlers.get(ext)


# ============================================================================
# BACKGROUND WORKER THREAD
# ============================================================================

class WorkerThread(QThread):
    """Background thread for crypto operations"""
    finished = Signal(bool, str)
    progress = Signal(int)
    
    def __init__(self, operation, **kwargs):
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
    
    def run(self):
        try:
            if self.operation == 'embed':
                self._embed()
            elif self.operation == 'extract':
                self._extract()
        except Exception as e:
            self.finished.emit(False, str(e))
    
    def _embed(self):
        try:
            input_file = self.kwargs['input_file']
            output_file = self.kwargs['output_file']
            data = self.kwargs['data']
            password = self.kwargs['password']
            
            self.progress.emit(25)
            
            # Encrypt
            encrypted = CryptoEngine.encrypt(data, password)
            
            self.progress.emit(50)
            
            # Get handler and embed
            handler = get_handler(input_file)
            if not handler:
                raise ValueError("Unsupported file format")
            
            handler.embed(input_file, encrypted, output_file)
            
            self.progress.emit(100)
            self.finished.emit(True, f"Success! Data embedded in:\n{output_file}")
            
        except Exception as e:
            self.finished.emit(False, f"Failed to embed: {str(e)}")
    
    def _extract(self):
        try:
            input_file = self.kwargs['input_file']
            password = self.kwargs['password']
            
            self.progress.emit(25)
            
            # Get handler and extract
            handler = get_handler(input_file)
            if not handler:
                raise ValueError("Unsupported file format")
            
            encrypted = handler.extract(input_file)
            if encrypted is None:
                raise ValueError("No embedded data found in file")
            
            self.progress.emit(50)
            
            # Decrypt
            try:
                plaintext = CryptoEngine.decrypt(encrypted, password)
            except InvalidTag:
                raise ValueError("Wrong password or corrupted data")
            
            self.progress.emit(100)
            
            # Try to decode as text
            try:
                text = plaintext.decode('utf-8')
                self.finished.emit(True, text)
            except UnicodeDecodeError:
                hex_data = plaintext.hex()
                self.finished.emit(True, f"[Binary data: {len(plaintext)} bytes]\n\nHex:\n{hex_data}")
            
        except Exception as e:
            self.finished.emit(False, f"Failed to extract: {str(e)}")


# ============================================================================
# MAIN GUI WINDOW
# ============================================================================

class MetaCryptWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MetaCrypt - Encrypted Metadata Embedding")
        self.setMinimumSize(900, 700)
        self.worker = None
        
        self.init_ui()
        self.apply_modern_style()
    
    def init_ui(self):
        """Initialize user interface"""
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        header_widget = QWidget()
        header_layout = QVBoxLayout(header_widget)
        header_layout.setSpacing(5)
        
        title = QLabel("🔒 MetaCrypt")
        title.setFont(QFont("Arial", 28, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(title)
        
        subtitle = QLabel("Encrypted Metadata Embedding System")
        subtitle.setFont(QFont("Arial", 12))
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #666;")
        header_layout.addWidget(subtitle)
        
        security_label = QLabel("AES-256-GCM • Argon2id • Cross-Platform")
        security_label.setFont(QFont("Arial", 9))
        security_label.setAlignment(Qt.AlignCenter)
        security_label.setStyleSheet("color: #888; margin-top: 5px;")
        header_layout.addWidget(security_label)
        
        layout.addWidget(header_widget)
        
        # Tabs
        tabs = QTabWidget()
        tabs.setFont(QFont("Arial", 10))
        tabs.addTab(self.create_embed_tab(), "📝 Embed Data")
        tabs.addTab(self.create_extract_tab(), "🔓 Extract Data")
        tabs.addTab(self.create_help_tab(), "ℹ️  Help & Info")
        layout.addWidget(tabs)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #ddd;
                border-radius: 5px;
                text-align: center;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setFont(QFont("Arial", 10))
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
    
    def create_embed_tab(self):
        """Create embed data tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # Step 1: File selection
        file_group = self.create_group_box("Step 1: Select Input File")
        file_layout = QVBoxLayout(file_group)
        
        file_row = QHBoxLayout()
        self.embed_file_input = QLineEdit()
        self.embed_file_input.setPlaceholderText("Click Browse to select a file...")
        self.embed_file_input.setReadOnly(True)
        file_row.addWidget(self.embed_file_input)
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.setMinimumWidth(120)
        browse_btn.clicked.connect(self.browse_embed_input)
        file_row.addWidget(browse_btn)
        file_layout.addLayout(file_row)
        
        format_label = QLabel("Supported: PNG, JPEG, PDF, MP3, MP4")
        format_label.setStyleSheet("color: #666; font-size: 9pt;")
        file_layout.addWidget(format_label)
        
        layout.addWidget(file_group)
        
        # Step 2: Data input
        data_group = self.create_group_box("Step 2: Enter Data to Embed")
        data_layout = QVBoxLayout(data_group)
        
        self.embed_data_input = QTextEdit()
        self.embed_data_input.setPlaceholderText("Type or paste the secret text you want to encrypt and embed...\n\nFor binary files, use 'Load from File' below.")
        self.embed_data_input.setMaximumHeight(150)
        data_layout.addWidget(self.embed_data_input)
        
        file_input_row = QHBoxLayout()
        file_input_label = QLabel("Or load from file:")
        file_input_row.addWidget(file_input_label)
        
        self.embed_data_file = QLineEdit()
        self.embed_data_file.setPlaceholderText("Optional: select a file to embed")
        file_input_row.addWidget(self.embed_data_file)
        
        data_file_btn = QPushButton("📄 Load File")
        data_file_btn.clicked.connect(self.browse_embed_data_file)
        file_input_row.addWidget(data_file_btn)
        data_layout.addLayout(file_input_row)
        
        layout.addWidget(data_group)
        
        # Step 3: Password
        pass_group = self.create_group_box("Step 3: Enter Encryption Password")
        pass_layout = QVBoxLayout(pass_group)
        
        pass_row = QHBoxLayout()
        self.embed_password = QLineEdit()
        self.embed_password.setEchoMode(QLineEdit.Password)
        self.embed_password.setPlaceholderText("Enter a strong password (20+ characters recommended)")
        pass_row.addWidget(self.embed_password)
        
        self.show_pass_embed = QCheckBox("Show")
        self.show_pass_embed.toggled.connect(lambda checked: 
            self.embed_password.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password))
        pass_row.addWidget(self.show_pass_embed)
        pass_layout.addLayout(pass_row)
        
        pass_hint = QLabel("⚠️  Use a strong, unique password. You'll need this exact password to decrypt later.")
        pass_hint.setStyleSheet("color: #ff6b6b; font-size: 9pt;")
        pass_layout.addWidget(pass_hint)
        
        layout.addWidget(pass_group)
        
        # Step 4: Output file
        output_group = self.create_group_box("Step 4: Select Output Location")
        output_layout = QVBoxLayout(output_group)
        
        output_row = QHBoxLayout()
        self.embed_output = QLineEdit()
        self.embed_output.setPlaceholderText("Output file will be auto-suggested after selecting input file")
        self.embed_output.setReadOnly(True)
        output_row.addWidget(self.embed_output)
        
        output_btn = QPushButton("💾 Change")
        output_btn.clicked.connect(self.browse_embed_output)
        output_row.addWidget(output_btn)
        output_layout.addLayout(output_row)
        
        layout.addWidget(output_group)
        
        # Embed button
        embed_btn = QPushButton("🔒 Embed & Encrypt Data")
        embed_btn.setMinimumHeight(50)
        embed_btn.setFont(QFont("Arial", 12, QFont.Bold))
        embed_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border-radius: 8px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
        """)
        embed_btn.clicked.connect(self.embed_data)
        layout.addWidget(embed_btn)
        
        layout.addStretch()
        return widget
    
    def create_extract_tab(self):
        """Create extract data tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        # Step 1: File selection
        file_group = self.create_group_box("Step 1: Select File with Embedded Data")
        file_layout = QVBoxLayout(file_group)
        
        file_row = QHBoxLayout()
        self.extract_file_input = QLineEdit()
        self.extract_file_input.setPlaceholderText("Select the file containing hidden data...")
        self.extract_file_input.setReadOnly(True)
        file_row.addWidget(self.extract_file_input)
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.setMinimumWidth(120)
        browse_btn.clicked.connect(self.browse_extract_input)
        file_row.addWidget(browse_btn)
        file_layout.addLayout(file_row)
        
        layout.addWidget(file_group)
        
        # Step 2: Password
        pass_group = self.create_group_box("Step 2: Enter Decryption Password")
        pass_layout = QVBoxLayout(pass_group)
        
        pass_row = QHBoxLayout()
        self.extract_password = QLineEdit()
        self.extract_password.setEchoMode(QLineEdit.Password)
        self.extract_password.setPlaceholderText("Enter the password used when embedding")
        pass_row.addWidget(self.extract_password)
        
        self.show_pass_extract = QCheckBox("Show")
        self.show_pass_extract.toggled.connect(lambda checked: 
            self.extract_password.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password))
        pass_row.addWidget(self.show_pass_extract)
        pass_layout.addLayout(pass_row)
        
        layout.addWidget(pass_group)
        
        # Extract button
        extract_btn = QPushButton("🔓 Extract & Decrypt Data")
        extract_btn.setMinimumHeight(50)
        extract_btn.setFont(QFont("Arial", 12, QFont.Bold))
        extract_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 8px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #0b7dda;
            }
            QPushButton:pressed {
                background-color: #0969c3;
            }