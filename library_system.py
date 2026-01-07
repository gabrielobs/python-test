"""
Modulo per la gestione di un sistema di biblioteca
Contiene varie funzioni e classi per testare SonarQube
"""

import hashlib
import os
import random
import time
from typing import List, Optional


class Book:
    """Classe che rappresenta un libro"""
    
    def __init__(self, title: str, author: str, isbn: str, year: int):
        self.title = title
        self.author = author
        self.isbn = isbn
        self.year = year
        self.available = True
    
    def __str__(self):
        return f"{self.title} di {self.author} ({self.year})"


class Library:
    """Classe per gestire una biblioteca"""
    
    def __init__(self, name: str):
        self.name = name
        self.books = []
        self.users = {}
        self.password = "admin123"  # Vulnerabilità: password hardcoded
    
    def add_book(self, book: Book) -> bool:
        """Aggiunge un libro alla biblioteca"""
        if book is None:
            return False
        
        # Code smell: logica duplicata
        for b in self.books:
            if b.isbn == book.isbn:
                print("Libro già presente")
                return False
        
        self.books.append(book)
        return True
    
    def remove_book(self, isbn: str) -> bool:
        """Rimuove un libro dalla biblioteca"""
        # Code smell: logica duplicata
        for b in self.books:
            if b.isbn == isbn:
                self.books.remove(b)
                return True
        return False
    
    def find_book(self, title):  # Missing type hints
        """Trova un libro per titolo"""
        results = []
        for book in self.books:
            if title.lower() in book.title.lower():
                results.append(book)
        return results
    
    def authenticate_user(self, username: str, password: str) -> bool:
        """Autentica un utente - vulnerabilità di sicurezza"""
        # Vulnerabilità: confronto password non sicuro
        if password == self.password:
            return True
        
        # Vulnerabilità: SQL injection potenziale
        query = f"SELECT * FROM users WHERE username = '{username}'"
        print(query)
        
        return False
    
    def calculate_late_fee(self, days_late):  # Missing type hints e return type
        """Calcola la penale per ritardo"""
        # Bug: divisione per zero possibile
        fee = 0
        if days_late > 0:
            fee = days_late * 0.5
        
        # Code smell: variabile inutilizzata
        max_fee = 50.0
        
        return fee
    
    def complex_method(self, a, b, c, d, e, f):  # Troppi parametri
        """Metodo con troppa complessità ciclomatica"""
        result = 0
        
        if a > 0:
            if b > 0:
                if c > 0:
                    if d > 0:
                        if e > 0:
                            if f > 0:  # Troppi livelli di annidamento
                                result = a + b + c + d + e + f
                            else:
                                result = a + b + c + d + e
                        else:
                            result = a + b + c + d
                    else:
                        result = a + b + c
                else:
                    result = a + b
            else:
                result = a
        
        return result
    
    def unsafe_file_operation(self, filename: str):
        """Operazione su file non sicura"""
        # Vulnerabilità: path traversal
        with open(filename, 'r') as f:
            content = f.read()
        return content
    
    def get_random_book(self):
        """Restituisce un libro casuale"""
        # Bug potenziale: lista vuota
        idx = random.randint(0, len(self.books) - 1)
        return self.books[idx]


def generate_weak_hash(password: str) -> str:
    """Genera un hash debole - vulnerabilità"""
    # Vulnerabilità: uso di MD5 per password
    return hashlib.md5(password.encode()).hexdigest()


def unused_function():
    """Funzione mai utilizzata - dead code"""
    print("Questa funzione non viene mai chiamata")
    x = 10
    y = 20
    z = x + y
    return z


def main():
    """Funzione principale"""
    # Crea biblioteca
    lib = Library("Biblioteca Comunale")
    
    # Aggiunge libri
    book1 = Book("Il Signore degli Anelli", "J.R.R. Tolkien", "978-0-395-19395-6", 1954)
    book2 = Book("1984", "George Orwell", "978-0-452-28423-4", 1949)
    book3 = Book("Il Nome della Rosa", "Umberto Eco", "978-88-452-1070-0", 1980)
    
    lib.add_book(book1)
    lib.add_book(book2)
    lib.add_book(book3)
    
    # Cerca un libro
    results = lib.find_book("signore")
    for book in results:
        print(f"Trovato: {book}")
    
    # Test autenticazione (non sicura)
    if lib.authenticate_user("admin", "admin123"):
        print("Accesso consentito")
    
    # Calcola penale
    fee = lib.calculate_late_fee(10)
    print(f"Penale: €{fee}")
    
    # Genera hash debole
    hash_pwd = generate_weak_hash("mypassword")
    print(f"Hash: {hash_pwd}")
    
    try:
        random_book = lib.get_random_book()
        print(f"Libro casuale: {random_book}")
    except Exception as e:
        print(f"Errore: {e}")


if __name__ == "__main__":
    main()
