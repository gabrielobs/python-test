"""
Sistema di gestione utenti e autenticazione
Contiene vulnerabilità di sicurezza e code smells per SonarQube
"""

import pickle
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime


class UserManager:
    """Gestione utenti con vulnerabilità di sicurezza"""
    
    def __init__(self):
        self.db_connection = None
        self.api_key = "sk_live_1234567890abcdef"  # Vulnerabilità: API key hardcoded
        self.secret_token = "my-secret-token-12345"  # Vulnerabilità: token hardcoded
        self.admin_password = "Admin@2024"  # Vulnerabilità: password hardcoded
    
    def connect_database(self, db_name):
        """Connessione al database - vulnerabilità SQL injection"""
        # Vulnerabilità: path injection
        self.db_connection = sqlite3.connect(db_name)
        return self.db_connection
    
    def create_user(self, username, password, email):
        """Crea un nuovo utente - SQL injection"""
        conn = self.connect_database("users.db")
        cursor = conn.cursor()
        
        # Vulnerabilità: SQL injection
        query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password}', '{email}')"
        cursor.execute(query)
        conn.commit()
        
        print(f"Utente {username} creato con successo")
        return True
    
    def authenticate_user(self, username, password):
        """Autenticazione utente - SQL injection e password in chiaro"""
        conn = self.connect_database("users.db")
        cursor = conn.cursor()
        
        # Vulnerabilità: SQL injection
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        result = cursor.fetchone()
        
        if result:
            print(f"Utente {username} autenticato")
            return True
        else:
            print("Autenticazione fallita")
            return False
    
    def get_user_by_id(self, user_id):
        """Recupera utente per ID - SQL injection"""
        conn = self.connect_database("users.db")
        cursor = conn.cursor()
        
        # Vulnerabilità: SQL injection (duplicazione del pattern vulnerabile)
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)
        result = cursor.fetchone()
        
        return result
    
    def delete_user(self, username):
        """Elimina utente - SQL injection"""
        conn = self.connect_database("users.db")
        cursor = conn.cursor()
        
        # Vulnerabilità: SQL injection (duplicazione del pattern vulnerabile)
        query = f"DELETE FROM users WHERE username = '{username}'"
        cursor.execute(query)
        conn.commit()
        
        print(f"Utente {username} eliminato")
        return True
    
    def update_user_email(self, username, new_email):
        """Aggiorna email utente - SQL injection"""
        conn = self.connect_database("users.db")
        cursor = conn.cursor()
        
        # Vulnerabilità: SQL injection (duplicazione del pattern vulnerabile)
        query = f"UPDATE users SET email = '{new_email}' WHERE username = '{username}'"
        cursor.execute(query)
        conn.commit()
        
        print(f"Email aggiornata per {username}")
        return True


class FileManager:
    """Gestione file con vulnerabilità"""
    
    def __init__(self):
        self.upload_path = "/var/www/uploads/"
    
    def read_file(self, filename):
        """Legge un file - path traversal"""
        # Vulnerabilità: path traversal
        file_path = self.upload_path + filename
        with open(file_path, 'r') as f:
            content = f.read()
        return content
    
    def write_file(self, filename, content):
        """Scrive un file - path traversal"""
        # Vulnerabilità: path traversal (duplicazione)
        file_path = self.upload_path + filename
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"File {filename} salvato")
        return True
    
    def delete_file(self, filename):
        """Elimina un file - path traversal"""
        # Vulnerabilità: path traversal (duplicazione)
        file_path = self.upload_path + filename
        import os
        os.remove(file_path)
        print(f"File {filename} eliminato")
        return True
    
    def load_pickle_data(self, filename):
        """Carica dati da pickle - insecure deserialization"""
        # Vulnerabilità: insecure deserialization
        file_path = self.upload_path + filename
        with open(file_path, 'rb') as f:
            data = pickle.load(f)
        return data
    
    def save_pickle_data(self, filename, data):
        """Salva dati in pickle"""
        file_path = self.upload_path + filename
        with open(file_path, 'wb') as f:
            pickle.dump(data, f)
        return True


class CommandExecutor:
    """Esecuzione comandi con vulnerabilità"""
    
    def __init__(self):
        self.allowed_commands = ["ls", "pwd", "date"]
    
    def execute_system_command(self, command):
        """Esegue un comando di sistema - command injection"""
        # Vulnerabilità: command injection
        result = subprocess.call(command, shell=True)
        return result
    
    def ping_host(self, hostname):
        """Ping a un host - command injection"""
        # Vulnerabilità: command injection (duplicazione)
        command = f"ping -c 4 {hostname}"
        result = subprocess.call(command, shell=True)
        return result
    
    def check_port(self, host, port):
        """Controlla se una porta è aperta - command injection"""
        # Vulnerabilità: command injection (duplicazione)
        command = f"nc -zv {host} {port}"
        result = subprocess.call(command, shell=True)
        return result
    
    def run_script(self, script_name):
        """Esegue uno script - command injection"""
        # Vulnerabilità: command injection (duplicazione)
        command = f"bash /scripts/{script_name}"
        result = subprocess.call(command, shell=True)
        return result


class XMLParser:
    """Parser XML con vulnerabilità"""
    
    def parse_xml_file(self, xml_file):
        """Parse di un file XML - XXE vulnerability"""
        # Vulnerabilità: XML External Entity (XXE)
        tree = ET.parse(xml_file)
        root = tree.getroot()
        return root
    
    def parse_xml_string(self, xml_string):
        """Parse di una stringa XML - XXE vulnerability"""
        # Vulnerabilità: XXE (duplicazione)
        root = ET.fromstring(xml_string)
        return root


class SessionManager:
    """Gestione sessioni con vulnerabilità"""
    
    def __init__(self):
        self.sessions = {}
        self.session_secret = "super-secret-key-123"  # Vulnerabilità: secret hardcoded
    
    def create_session(self, user_id):
        """Crea una sessione - weak random"""
        import random
        # Vulnerabilità: weak random per token di sicurezza
        session_id = str(random.randint(1000, 9999))
        self.sessions[session_id] = {
            'user_id': user_id,
            'created_at': datetime.now()
        }
        return session_id
    
    def validate_session(self, session_id):
        """Valida una sessione"""
        if session_id in self.sessions:
            return True
        return False
    
    def generate_token(self, username):
        """Genera un token - weak crypto"""
        import hashlib
        # Vulnerabilità: uso di MD5 (duplicazione del pattern)
        token = hashlib.md5(username.encode()).hexdigest()
        return token
    
    def generate_api_token(self, user_id):
        """Genera un token API - weak crypto"""
        import hashlib
        # Vulnerabilità: uso di MD5 (duplicazione)
        token = hashlib.md5(str(user_id).encode()).hexdigest()
        return token


class PasswordValidator:
    """Validazione password con logica duplicata"""
    
    def validate_admin_password(self, password):
        """Valida password admin - logica duplicata"""
        if len(password) < 8:
            print("Password troppo corta")
            return False
        if not any(c.isupper() for c in password):
            print("Password deve contenere maiuscole")
            return False
        if not any(c.isdigit() for c in password):
            print("Password deve contenere numeri")
            return False
        if not any(c in "!@#$%^&*" for c in password):
            print("Password deve contenere caratteri speciali")
            return False
        return True
    
    def validate_user_password(self, password):
        """Valida password utente - logica duplicata"""
        if len(password) < 8:
            print("Password troppo corta")
            return False
        if not any(c.isupper() for c in password):
            print("Password deve contenere maiuscole")
            return False
        if not any(c.isdigit() for c in password):
            print("Password deve contenere numeri")
            return False
        if not any(c in "!@#$%^&*" for c in password):
            print("Password deve contenere caratteri speciali")
            return False
        return True
    
    def validate_temp_password(self, password):
        """Valida password temporanea - logica duplicata"""
        if len(password) < 8:
            print("Password troppo corta")
            return False
        if not any(c.isupper() for c in password):
            print("Password deve contenere maiuscole")
            return False
        if not any(c.isdigit() for c in password):
            print("Password deve contenere numeri")
            return False
        if not any(c in "!@#$%^&*" for c in password):
            print("Password deve contenere caratteri speciali")
            return False
        return True


def main():
    """Funzione principale per test"""
    # Test UserManager
    user_mgr = UserManager()
    user_mgr.create_user("admin", "password123", "admin@example.com")
    user_mgr.authenticate_user("admin", "password123")
    
    # Test FileManager
    file_mgr = FileManager()
    file_mgr.write_file("test.txt", "Hello World")
    
    # Test CommandExecutor
    cmd_exec = CommandExecutor()
    cmd_exec.ping_host("localhost")
    
    # Test SessionManager
    session_mgr = SessionManager()
    session_id = session_mgr.create_session(1)
    print(f"Session ID: {session_id}")
    
    # Test PasswordValidator
    pwd_validator = PasswordValidator()
    pwd_validator.validate_admin_password("Test@123")


if __name__ == "__main__":
    main()
