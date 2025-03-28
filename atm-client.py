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
import threading

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
        
        # Setup preestablished key
        self.setup_preestablished_key()

        self.connect_timer()
        
        # Setup GUI
        self.setup_gui()

    def connect_timer(self):
        threading.Thread(target=self.connect).start()

    
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
            exit(0)

    
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
        button_frame.pack(pady=10)
        
        self.deposit_button = tk.Button(button_frame, text="Deposit", command=self.deposit, width=10)
        self.deposit_button.grid(row=0, column=0, padx=5)
        
        self.withdraw_button = tk.Button(button_frame, text="Withdraw", command=self.withdraw, width=10)
        self.withdraw_button.grid(row=0, column=1, padx=5)
        
        self.balance_button = tk.Button(button_frame, text="Check Balance", command=self.check_balance, width=15)
        self.balance_button.grid(row=1, column=0, columnspan=2, pady=10)
        
        # Logout button
        self.logout_button = tk.Button(self.transaction_frame, text="Logout", command=self.logout)
        self.logout_button.pack(pady=20)
    
    def connect(self):
        while (not self.connected):
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.server_host, self.server_port))
                
                # Send ATM ID
                self.send_message({'type': 'atm_id', 'atm_id': self.atm_id})
                
                # Receive response
                response = self.receive_message()
                
                if response and response.get('type') == 'atm_accepted':
                    self.connected = True
                    self.status_var.set("Connected")
                    #self.connect_button.config(text="Disconnect", command=self.disconnect)
                    self.login_button.config(state=tk.NORMAL)
                    self.create_account_button.config(state=tk.NORMAL)
                    messagebox.showinfo("Connection", "Successfully connected to bank server")
                else:
                    messagebox.showerror("Connection Error", "Failed to connect to bank server")
                    self.socket.close()
                    self.socket = None
            except Exception as e:
                messagebox.showerror("Connection Error", f"Failed to connect: {str(e)} \nRetrying in 10 seconds")
                if self.socket:
                    self.socket.close()
                    self.socket = None
            time.sleep(10)
    
    def disconnect(self):
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            finally:
                self.socket = None
        
        self.connected = False
        self.status_var.set("Disconnected")
        #self.connect_button.config(text="Connect to Bank", command=self.connect)
        self.login_button.config(state=tk.DISABLED)
        self.create_account_button.config(state=tk.DISABLED)
        
        # Clear security attributes
        self.username = None
        self.master_secret = None
        self.encryption_key = None
        self.mac_key = None
        
        # Reset to login frame
        self.setup_login_frame()
    
    def send_message(self, message):
        """Send a plain (unencrypted) message to the server"""
        if not self.socket:
            return False
        
        try:
            data = json.dumps(message).encode('utf-8')
            self.socket.send(data)
            return True
        except Exception as e:
            print(f"Error sending message: {e}")
            return False
    
    def receive_message(self):
        """Receive a plain (unencrypted) message from the server"""
        if not self.socket:
            return None
        
        try:
            data = self.socket.recv(1024).decode('utf-8')
            if not data:
                return None
            return json.loads(data)
        except Exception as e:
            print(f"Error receiving message: {e}")
            return None
    
    def send_secure_message(self, message):
        """Send an encrypted message to the server with MAC"""
        if not self.socket or not self.encryption_key or not self.mac_key:
            return False
        
        try:
            # Convert message to JSON and encode
            message_data = json.dumps(message).encode('utf-8')
            
            # Encrypt message
            encrypted_data = self.encrypt(message_data, self.encryption_key)
            
            # Generate MAC
            mac = self.generate_mac(encrypted_data, self.mac_key)
            
            # Send encrypted data + MAC
            self.socket.send(encrypted_data + mac)
            return True
        except Exception as e:
            print(f"Error sending secure message: {e}")
            return False
    
    def receive_secure_message(self):
        """Receive an encrypted message from the server and verify MAC"""
        if not self.socket or not self.encryption_key or not self.mac_key:
            return None
        
        try:
            # Receive data
            data = self.socket.recv(4096)
            if not data:
                return None
            
            # Extract MAC and encrypted message
            mac_size = 32  # SHA-256 produces 32-byte MACs
            received_mac = data[-mac_size:]
            encrypted_message = data[:-mac_size]
            
            # Verify MAC
            if not self.verify_mac(encrypted_message, received_mac, self.mac_key):
                print("MAC verification failed")
                return None
            
            # Decrypt message
            decrypted_data = self.decrypt(encrypted_message, self.encryption_key)
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            print(f"Error receiving secure message: {e}")
            return None
    
    def encrypt(self, data, key):
        """Encrypt data using AES-CBC with the given key"""
        iv = os.urandom(16)  # 128-bit random IV
        
        # Apply padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + ciphertext
        return iv + ciphertext
    
    def decrypt(self, encrypted_data, key):
        """Decrypt data using AES-CBC with the given key"""
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    
    def derive_keys(self, master_secret):
        """Derive encryption and MAC keys from the master secret"""
        # Use PBKDF2 to derive two separate keys
        # For encryption key
        kdf1 = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"encryption_key_salt",
            iterations=100000,
            backend=default_backend()
        )
        encryption_key = kdf1.derive(master_secret)
        
        # For MAC key
        kdf2 = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"mac_key_salt",
            iterations=100000,
            backend=default_backend()
        )
        mac_key = kdf2.derive(master_secret)
        
        return encryption_key, mac_key
    
    def generate_mac(self, data, mac_key):
        """Generate MAC for data integrity"""
        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize()
    
    def verify_mac(self, data, mac, mac_key):
        """Verify MAC for data integrity"""
        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        try:
            h.verify(mac)
            return True
        except Exception:
            return False
    
    def login(self):
        if not self.connected:
            messagebox.showerror("Error", "Not connected to the server")
            return
        
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        # Send login request
        login_request = {
            'type': 'login',
            'username': username,
            'password': password
        }
        
        if not self.send_message(login_request):
            messagebox.showerror("Error", "Failed to send login request")
            return
        
        # Start authenticated key distribution protocol
        if self.key_distribution_protocol(username):
            # Authentication successful, switch to transaction frame
            self.username = username
            self.setup_transaction_frame()
            self.check_balance()  # Get initial balance
        else:
            messagebox.showerror("Login Failed", "Invalid credentials or authentication error")
    
    def create_account(self):
        if not self.connected:
            messagebox.showerror("Error", "Not connected to the server")
            return
        
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        # Send account creation request
        create_request = {
            'type': 'create_account',
            'username': username,
            'password': password
        }
        
        if not self.send_message(create_request):
            messagebox.showerror("Error", "Failed to send account creation request")
            return
        
        # Receive response
        response = self.receive_message()
        
        if response and response.get('success'):
            messagebox.showinfo("Success", "Account created successfully! You can now login.")
        else:
            messagebox.showerror("Error", response.get('message', "Failed to create account"))
    
    def key_distribution_protocol(self, username):
        try:
            # 1. Wait for challenge from server
            response = self.receive_message()
            
            if not response or response.get('type') != 'auth_challenge':
                return False
            
            # 2. Decode server's challenge
            server_challenge = base64.b64decode(response['challenge'])
            
            # 3. Generate our own challenge
            atm_challenge = os.urandom(16)
            
            # 4. Sign server's challenge with shared key
            h = hmac.HMAC(self.shared_key, hashes.SHA256(), backend=default_backend())
            h.update(server_challenge)
            signed_server_challenge = h.finalize()
            
            # 5. Send our challenge and signed server challenge
            auth_response = {
                'type': 'auth_response',
                'atm_challenge': base64.b64encode(atm_challenge).decode('utf-8'),
                'signed_server_challenge': base64.b64encode(signed_server_challenge).decode('utf-8')
            }
            
            if not self.send_message(auth_response):
                return False
            
            # 6. Receive server's response
            server_response = self.receive_message()
            
            if not server_response or server_response.get('type') != 'auth_result' or not server_response.get('success'):
                return False
            
            # 7. Verify server's signature on our challenge
            signed_atm_challenge = base64.b64decode(server_response['signed_atm_challenge'])
            
            h = hmac.HMAC(self.shared_key, hashes.SHA256(), backend=default_backend())
            h.update(atm_challenge)
            expected_signature = h.finalize()
            
            if not self.constant_time_compare(signed_atm_challenge, expected_signature):
                print("Server authentication failed: signature mismatch")
                return False
            
            # 8. Decrypt the master secret
            encrypted_master_secret = base64.b64decode(server_response['encrypted_master_secret'])
            self.master_secret = self.decrypt(encrypted_master_secret, self.shared_key)
            
            # 9. Derive encryption and MAC keys
            self.encryption_key, self.mac_key = self.derive_keys(self.master_secret)
            
            return True
        
        except Exception as e:
            print(f"Error in key distribution protocol: {e}")
            return False
    
    def constant_time_compare(self, a, b):
        """Compare two byte strings in constant time to avoid timing attacks"""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0
    
    def check_balance(self):
        if not self.connected or not self.username:
            return
        
        # Send balance inquiry request
        if self.send_secure_message({'type': 'balance'}):
            # Receive response
            response = self.receive_secure_message()
            
            if response and response.get('success'):
                balance = response.get('balance', 0.0)
                self.balance_var.set(f"Balance: ${balance:.2f}")
            else:
                messagebox.showerror("Error", response.get('message', "Failed to get balance"))
        else:
            messagebox.showerror("Error", "Failed to send balance request")
    
    def deposit(self):
        if not self.connected or not self.username:
            return
        
        try:
            amount = float(self.amount_entry.get())
            if amount <= 0:
                messagebox.showerror("Error", "Please enter a positive amount")
                return
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid amount")
            return
        
        # Send deposit request
        if self.send_secure_message({'type': 'deposit', 'amount': amount}):
            # Receive response
            response = self.receive_secure_message()
            
            if response and response.get('success'):
                messagebox.showinfo("Success", response.get('message', "Deposit successful"))
                self.balance_var.set(f"Balance: ${response.get('balance', 0.0):.2f}")
                self.amount_entry.delete(0, tk.END)
            else:
                messagebox.showerror("Error", response.get('message', "Deposit failed"))
        else:
            messagebox.showerror("Error", "Failed to send deposit request")
    
    def withdraw(self):
        if not self.connected or not self.username:
            return
        
        try:
            amount = float(self.amount_entry.get())
            if amount <= 0:
                messagebox.showerror("Error", "Please enter a positive amount")
                return
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid amount")
            return
        
        # Send withdrawal request
        if self.send_secure_message({'type': 'withdraw', 'amount': amount}):
            # Receive response
            response = self.receive_secure_message()
            
            if response and response.get('success'):
                messagebox.showinfo("Success", response.get('message', "Withdrawal successful"))
                self.balance_var.set(f"Balance: ${response.get('balance', 0.0):.2f}")
                self.amount_entry.delete(0, tk.END)
            else:
                messagebox.showerror("Error", response.get('message', "Withdrawal failed"))
        else:
            messagebox.showerror("Error", "Failed to send withdrawal request")
    
    def logout(self):
        self.disconnect()
        self.setup_login_frame()
        self.status_var.set("Connected")
        self.connect_button.config(text="Disconnect", command=self.disconnect)
        self.login_button.config(state=tk.NORMAL)
        self.create_account_button.config(state=tk.NORMAL)

# Main entry point
def main():
    import sys
    
    # Default ATM ID
    atm_id = "atm1"
    
    # Check if an ATM ID was provided as a command-line argument
    if len(sys.argv) > 1:
        atm_id = sys.argv[1]
    
    # Create and run ATM client
    client = ATMClient(atm_id)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"Error: {e}")
        print(traceback.format_exc())
        input("Press Enter to exit...")  # Keep terminal open to see the error