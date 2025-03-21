# atm_client.py
import socket
import json
import os
import base64
import hashlib
import time
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class ATMClient:
    def __init__(self, atm_id, server_host='127.0.0.1', server_port=9999):
        self.atm_id = atm_id
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.connected = False
        
        # Authentication and security attributes
        self.username = None
        self.shared_key = None  # Pre-established shared key with server
        self.master_secret = None  # Key established during authentication
        self.encryption_key = None  # Key derived from master secret for encryption
        self.mac_key = None  # Key derived from master secret for MAC
        
        # GUI attributes
        self.root = None
        self.login_frame = None
        self.transaction_frame = None
        self.status_var = None
        
        # Setup preestablished key
        self.setup_preestablished_key()
        
        # Setup GUI
        self.setup_gui()
    
    def setup_preestablished_key(self):
        # In a real system, this would be securely distributed and stored
        self.shared_key = hashlib.sha256(f"shared_key_{self.atm_id}".encode()).digest()
    
    def setup_gui(self):
        self.root = tk.Tk()
        self.root.title(f"ATM Client - {self.atm_id}")
        self.root.geometry("500x450")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Status bar
        status_frame = tk.Frame(self.root)
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(status_frame, text="Status:").pack(side=tk.LEFT)
        self.status_var = tk.StringVar(value="Disconnected")
        tk.Label(status_frame, textvariable=self.status_var, fg="red").pack(side=tk.LEFT, padx=5)
        
        # Button to connect to server
        self.connect_button = tk.Button(status_frame, text="Connect to Bank", command=self.connect)
        self.connect_button.pack(side=tk.RIGHT)
        
        # Container for frames
        self.container = tk.Frame(self.root)
        self.container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Setup initial login frame
        self.setup_login_frame()
        
        # Center window
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
        # Start GUI
        self.root.mainloop()
    
    def on_closing(self):
        if messagebox.askokcancel("Exit", "Do you want to exit the ATM?"):
            self.disconnect()
            self.root.destroy()
    
    def setup_login_frame(self):
        # Clear container first
        for widget in self.container.winfo_children():
            widget.destroy()
        
        # Create login frame
        self.login_frame = tk.Frame(self.container)
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        tk.Label(self.login_frame, text="Welcome to Secure Banking System", font=("Arial", 16)).pack(pady=20)
        
        # Username and password fields
        credentials_frame = tk.Frame(self.login_frame)
        credentials_frame.pack(pady=10)
        
        tk.Label(credentials_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.username_entry = tk.Entry(credentials_frame, width=25)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(credentials_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.password_entry = tk.Entry(credentials_frame, width=25, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Login and Create Account buttons
        button_frame = tk.Frame(self.login_frame)
        button_frame.pack(pady=20)
        
        self.login_button = tk.Button(button_frame, text="Login", command=self.login, state=tk.DISABLED)
        self.login_button.grid(row=0, column=0, padx=10)
        
        self.create_account_button = tk.Button(button_frame, text="Create Account", command=self.create_account, state=tk.DISABLED)
        self.create_account_button.grid(row=0, column=1, padx=10)
    
    def setup_transaction_frame(self):
        # Clear container first
        for widget in self.container.winfo_children():
            widget.destroy()
        
        # Create transaction frame
        self.transaction_frame = tk.Frame(self.container)
        self.transaction_frame.pack(fill=tk.BOTH, expand=True)
        
        # Welcome message
        tk.Label(
            self.transaction_frame, 
            text=f"Welcome, {self.username}", 
            font=("Arial", 16)
        ).pack(pady=10)
        
        # Balance display
        self.balance_var = tk.StringVar(value="Balance: $0.00")
        balance_label = tk.Label(
            self.transaction_frame,
            textvariable=self.balance_var,
            font=("Arial", 14),
            bg="#e6e6e6",
            padx=10,
            pady=5,
            relief=tk.RIDGE
        )
        balance_label.pack(pady=15)
        
        # Transaction options
        options_frame = tk.Frame(self.transaction_frame)
        options_frame.pack(pady=20)
        
        # Amount entry for deposit/withdraw
        amount_frame = tk.Frame(options_frame)
        amount_frame.pack(pady=10)
        
        tk.Label(amount_frame, text="Amount: $").pack(side=tk.LEFT)
        self.amount_entry = tk.Entry(amount_frame, width=15)
        self.amount_entry.pack(side=tk.LEFT)
        
        # Transaction buttons
        button_frame = tk.Frame(options_frame)
        button_frame