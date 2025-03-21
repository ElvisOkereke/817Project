# bank_server.py
import socket
import threading
import json
import os
import base64
import time
import hashlib
import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class BankServer:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}  # Store active client connections
        self.accounts = {}  # Store account information
        self.preestablished_keys = {}  # Preestablished shared keys with clients
        self.active_sessions = {}  # Active session information
        
        # Load accounts from file if exists
        self.load_accounts()
        # Setup preestablished keys (in a real system, these would be securely distributed)
        self.setup_preestablished_keys()
        
        # Create directory for audit logs if it doesn't exist
        if not os.path.exists("audit_logs"):
            os.makedirs("audit_logs")
            
        # Start the GUI in a separate thread
        self.gui_thread = threading.Thread(target=self.setup_gui)
        self.gui_thread.daemon = True
        self.gui_thread.start()
    
    def setup_gui(self):
        self.root = tk.Tk()
        self.root.title("Bank Server")
        self.root.geometry("700x500")
        
        # Server status
        status_frame = tk.Frame(self.root)
        status_frame.pack(pady=10)
        
        tk.Label(status_frame, text="Server Status:").grid(row=0, column=0, padx=5)
        self.status_label = tk.Label(status_frame, text="Not Started", fg="red")
        self.status_label.grid(row=0, column=1, padx=5)
        
        # Start/Stop buttons
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=5)
        
        self.start_btn = tk.Button(btn_frame, text="Start Server", command=self.start_server_gui)
        self.start_btn.grid(row=0, column=0, padx=10)
        
        self.stop_btn = tk.Button(btn_frame, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=1, padx=10)
        
        # Log area
        log_frame = tk.Frame(self.root)
        log_frame.pack(pady=10, fill=tk.BOTH, expand=True)
        
        tk.Label(log_frame, text="Server Log:").pack(anchor="w")
        
        self.log_area = scrolledtext.ScrolledText(log_frame, height=15)
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=10)
        
        # Account management area
        account_frame = tk.Frame(self.root)
        account_frame.pack(pady=10, fill=tk.X)
        
        tk.Label(account_frame, text="Connected Clients:").pack(anchor="w")
        
        self.clients_listbox = tk.Listbox(account_frame, height=5)
        self.clients_listbox.pack(fill=tk.X, padx=10)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def log_to_gui(self, message):
        if hasattr(self, 'log_area'):
            self.log_area.insert(tk.END, f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
            self.log_area.see(tk.END)
    
    def update_client_list(self):
        if hasattr(self, 'clients_listbox'):
            self.clients_listbox.delete(0, tk.END)
            for username in self.active_sessions:
                self.clients_listbox.insert(tk.END, f"{username} - Connected")
    
    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit the server?"):
            self.stop_server()
            self.root.destroy()
            os._exit(0)
    
    def start_server_gui(self):
        self.start_server()
        self.status_label.config(text="Running", fg="green")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
    
    def load_accounts(self):
        try:
            if os.path.exists('accounts.json'):
                with open('accounts.json', 'r') as f:
                    self.accounts = json.load(f)
                self.log_to_gui(f"Loaded {len(self.accounts)} accounts from file")
        except Exception as e:
            print(f"Error loading accounts: {e}")
            self.accounts = {}
    
    def save_accounts(self):
        try:
            with open('accounts.json', 'w') as f:
                json.dump(self.accounts, f)
        except Exception as e:
            print(f"Error saving accounts: {e}")
    
    def setup_preestablished_keys(self):
        # In a real-world scenario, these keys would be securely distributed
        # For this project, we're using predefined keys for simplicity
        self.preestablished_keys = {
            "atm1": hashlib.sha256(b"shared_key_atm1").digest(),
            "atm2": hashlib.sha256(b"shared_key_atm2").digest(),
            "atm3": hashlib.sha256(b"shared_key_atm3").digest()
        }
    
    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        print(f"Server started on {self.host}:{self.port}")
        self.log_to_gui(f"Server started on {self.host}:{self.port}")
        
        # Start accepting connections in a separate thread
        accept_thread = threading.Thread(target=self.accept_connections)
        accept_thread.daemon = True
        accept_thread.start()
    
    def stop_server(self):
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
            self.log_to_gui("Server stopped")
            if hasattr(self, 'status_label'):
                self.status_label.config(text="Stopped", fg="red")
                self.start_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
    
    def accept_connections(self):
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_handler.daemon = True
                client_handler.start()
                self.log_to_gui(f"New connection from {address[0]}:{address[1]}")
            except:
                break
    
    def handle_client(self, client_socket, address):
        atm_id = None
        username = None
        
        try:
            # First message should be ATM ID
            data = client_socket.recv(1024).decode('utf-8')
            message = json.loads(data)
            
            if message['type'] == 'atm_id':
                atm_id = message['atm_id']
                if atm_id not in self.preestablished_keys:
                    client_socket.send(json.dumps({'type': 'error', 'message': 'Unknown ATM'}).encode('utf-8'))
                    client_socket.close()
                    return
                
                # Send acknowledgment
                client_socket.send(json.dumps({'type': 'atm_accepted'}).encode('utf-8'))
                self.log_to_gui(f"ATM {atm_id} authenticated")
                
                # Wait for account creation or login
                while True:
                    data = client_socket.recv(1024).decode('utf-8')
                    if not data:
                        break
                    
                    message = json.loads(data)
                    
                    if message['type'] == 'create_account':
                        self.handle_account_creation(client_socket, message)
                    
                    elif message['type'] == 'login':
                        username = message['username']
                        password = message['password']
                        
                        # Verify credentials
                        if self.verify_credentials(username, password):
                            # Start key distribution protocol
                            self.key_distribution_protocol(client_socket, atm_id, username)
                            break
                        else:
                            client_socket.send(json.dumps({
                                'type': 'login_response', 
                                'success': False,
                                'message': 'Invalid credentials'
                            }).encode('utf-8'))
            
            # Handle transactions with the authenticated client
            if username and atm_id:
                self.process_transactions(client_socket, atm_id, username)
        
        except Exception as e:
            print(f"Error handling client: {e}")
            self.log_to_gui(f"Error with client {address}: {e}")
        finally:
            if username and username in self.active_sessions:
                del self.active_sessions[username]
                self.update_client_list()
            client_socket.close()
            self.log_to_gui(f"Connection closed with {address[0]}:{address[1]}")
    
    def handle_account_creation(self, client_socket, message):
        username = message['username']
        password = message['password']
        
        if username in self.accounts:
            client_socket.send(json.dumps({
                'type': 'account_creation_response',
                'success': False,
                'message': 'Username already exists'
            }).encode('utf-8'))
            return
        
        # Hash password before storing
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        # Create account
        self.accounts[username] = {
            'password': hashed_password,
            'balance': 0.0,
            'transactions': []
        }
        
        # Save accounts to file
        self.save_accounts()
        
        client_socket.send(json.dumps({
            'type': 'account_creation_response',
            'success': True,
            'message': 'Account created successfully'
        }).encode('utf-8'))
        
        self.log_to_gui(f"New account created: {username}")
    
    def verify_credentials(self, username, password):
        if username not in self.accounts:
            return False
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        return self.accounts[username]['password'] == hashed_password
    
    def key_distribution_protocol(self, client_socket, atm_id, username):
        # 1. Get the preestablished shared key for this ATM
        shared_key = self.preestablished_keys[atm_id]
        
        # 2. Generate a random challenge
        server_challenge = os.urandom(16)
        
        # 3. Send challenge to ATM
        challenge_message = {
            'type': 'auth_challenge',
            'challenge': base64.b64encode(server_challenge).decode('utf-8')
        }
        client_socket.send(json.dumps(challenge_message).encode('utf-8'))
        
        # 4. Receive response from ATM
        data = client_socket.recv(1024).decode('utf-8')
        message = json.loads(data)
        
        if message['type'] != 'auth_response':
            client_socket.send(json.dumps({
                'type': 'auth_result',
                'success': False,
                'message': 'Authentication protocol error'
            }).encode('utf-8'))
            return False
        
        # 5. Decode ATM's response
        atm_challenge = base64.b64decode(message['atm_challenge'])
        signed_server_challenge = base64.b64decode(message['signed_server_challenge'])
        
        # 6. Verify that the ATM correctly signed our challenge
        h = hmac.HMAC(shared_key, hashes.SHA256(), backend=default_backend())
        h.update(server_challenge)
        expected_signature = h.finalize()
        
        if not self.constant_time_compare(signed_server_challenge, expected_signature):
            client_socket.send(json.dumps({
                'type': 'auth_result',
                'success': False,
                'message': 'Client authentication failed'
            }).encode('utf-8'))
            return False
        
        # 7. Sign ATM's challenge
        h = hmac.HMAC(shared_key, hashes.SHA256(), backend=default_backend())
        h.update(atm_challenge)
        signed_atm_challenge = h.finalize()
        
        # 8. Generate Master Secret
        master_secret = os.urandom(32)  # 256-bit random key
        
        # 9. Encrypt the master secret with the shared key
        encrypted_master_secret = self.encrypt(master_secret, shared_key)
        
        # 10. Send response back to ATM
        response = {
            'type': 'auth_result',
            'success': True,
            'signed_atm_challenge': base64.b64encode(signed_atm_challenge).decode('utf-8'),
            'encrypted_master_secret': base64.b64encode(encrypted_master_secret).decode('utf-8')
        }
        client_socket.send(json.dumps(response).encode('utf-8'))
        
        # 11. Derive encryption and MAC keys from master secret
        encryption_key, mac_key = self.derive_keys(master_secret)
        
        # 12. Store the session keys
        self.active_sessions[username] = {
            'atm_id': atm_id,
            'master_secret': master_secret,
            'encryption_key': encryption_key,
            'mac_key': mac_key
        }
        
        self.update_client_list()
        self.log_to_gui(f"User {username} authenticated from ATM {atm_id}")
        return True
    
    def constant_time_compare(self, a, b):
        """Compare two byte strings in constant time to avoid timing attacks"""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0
    
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
    
    def process_transactions(self, client_socket, atm_id, username):
        session = self.active_sessions.get(username)
        if not session:
            return
        
        encryption_key = session['encryption_key']
        mac_key = session['mac_key']
        
        while True:
            try:
                # Receive encrypted data from client
                data = client_socket.recv(4096)
                if not data:
                    break
                
                # Extract MAC and encrypted message
                mac_size = 32  # SHA-256 produces 32-byte MACs
                received_mac = data[-mac_size:]
                encrypted_message = data[:-mac_size]
                
                # Verify MAC
                if not self.verify_mac(encrypted_message, received_mac, mac_key):
                    error_response = {'type': 'error', 'message': 'Message integrity check failed'}
                    encrypted_response = self.encrypt(json.dumps(error_response).encode('utf-8'), encryption_key)
                    response_mac = self.generate_mac(encrypted_response, mac_key)
                    client_socket.send(encrypted_response + response_mac)
                    continue
                
                # Decrypt message
                try:
                    decrypted_data = self.decrypt(encrypted_message, encryption_key)
                    message = json.loads(decrypted_data.decode('utf-8'))
                except Exception as e:
                    error_response = {'type': 'error', 'message': f'Decryption error: {str(e)}'}
                    encrypted_response = self.encrypt(json.dumps(error_response).encode('utf-8'), encryption_key)
                    response_mac = self.generate_mac(encrypted_response, mac_key)
                    client_socket.send(encrypted_response + response_mac)
                    continue
                
                # Process transaction based on message type
                response = self.handle_transaction(username, message)
                
                # Encrypt response
                encrypted_response = self.encrypt(json.dumps(response).encode('utf-8'), encryption_key)
                
                # Generate MAC for response
                response_mac = self.generate_mac(encrypted_response, mac_key)
                
                # Send response
                client_socket.send(encrypted_response + response_mac)
                
            except Exception as e:
                print(f"Error processing transaction: {e}")
                self.log_to_gui(f"Transaction error for {username}: {e}")
                break
    
    def handle_transaction(self, username, message):
        transaction_type = message.get('type')
        response = {'type': f'{transaction_type}_response', 'success': False}
        
        if username not in self.accounts:
            response['message'] = 'Account not found'
            return response
        
        account = self.accounts[username]
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        
        if transaction_type == 'balance':
            response['success'] = True
            response['balance'] = account['balance']
            response['message'] = f'Current balance: ${account["balance"]:.2f}'
            
            # Log the transaction
            self.log_transaction(username, 'balance inquiry', timestamp)
            
        elif transaction_type == 'deposit':
            amount = float(message.get('amount', 0))
            if amount <= 0:
                response['message'] = 'Invalid deposit amount'
            else:
                account['balance'] += amount
                
                # Log transaction
                account['transactions'].append({
                    'type': 'deposit',
                    'amount': amount,
                    'timestamp': timestamp
                })
                
                self.log_transaction(username, f'deposit ${amount:.2f}', timestamp)
                self.save_accounts()
                
                response['success'] = True
                response['balance'] = account['balance']
                response['message'] = f'Deposited ${amount:.2f}. New balance: ${account["balance"]:.2f}'
                
        elif transaction_type == 'withdraw':
            amount = float(message.get('amount', 0))
            if amount <= 0:
                response['message'] = 'Invalid withdrawal amount'
            elif amount > account['balance']:
                response['message'] = 'Insufficient funds'
            else:
                account['balance'] -= amount
                
                # Log transaction
                account['transactions'].append({
                    'type': 'withdrawal',
                    'amount': amount,
                    'timestamp': timestamp
                })
                
                self.log_transaction(username, f'withdraw ${amount:.2f}', timestamp)
                self.save_accounts()
                
                response['success'] = True
                response['balance'] = account['balance']
                response['message'] = f'Withdrew ${amount:.2f}. New balance: ${account["balance"]:.2f}'
                
        else:
            response['message'] = 'Unknown transaction type'
        
        self.log_to_gui(f"Transaction - User: {username}, Type: {transaction_type}, Status: {'Success' if response['success'] else 'Failed'}")
        return response
    
    def log_transaction(self, username, action, timestamp):
        """Create encrypted audit log entry"""
        session = self.active_sessions.get(username)
        if not session:
            return
        
        encryption_key = session['encryption_key']
        
        # Create log entry
        log_entry = f"{username} {action} {timestamp}\n"
        
        # Encrypt log entry
        encrypted_entry = self.encrypt(log_entry.encode('utf-8'), encryption_key)
        encoded_entry = base64.b64encode(encrypted_entry)
        
        # Write to audit log file
        log_file_path = os.path.join("audit_logs", f"audit_log_{time.strftime('%Y%m%d')}.log")
        with open(log_file_path, 'ab') as f:
            f.write(encoded_entry + b'\n')

if __name__ == "__main__":
    server = BankServer()
    server.setup_gui()
