from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from phe import paillier
from bitarray import bitarray
import hashlib
import os
from tkinter import Tk, filedialog

class PrivacyPreservingSearch:
    def __init__(self, sym_key_size=16, bloom_filter_size=1000, hash_count=3, max_phrase_length=5):
        # Initialize attributes: symmetric key for AES, Paillier keys, Bloom filter, etc.
        self.sym_key = os.urandom(sym_key_size)
        self.block_size = AES.block_size
        self.public_key, self.private_key = paillier.generate_paillier_keypair()
        self.bloom_filter = bitarray(bloom_filter_size)
        self.bloom_filter.setall(0)
        self.hash_count = hash_count
        self.bloom_filter_size = bloom_filter_size
        self.hash_table = {}
        self.phrase_to_files = {}
        self.max_phrase_length = max_phrase_length

    def _derive_iv(self, phrase):
        """
        Derive a consistent IV based on the hash of the phrase.
        """
        return hashlib.sha256(phrase.encode()).digest()[:self.block_size]

    def encrypt_symmetric(self, data):
        """
        Encrypt the given data using AES (CBC mode) with a derived IV.
        """
        iv = self._derive_iv(data)
        cipher = AES.new(self.sym_key, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(data.encode(), self.block_size))
        return iv, ciphertext

    def decrypt_symmetric(self, iv, ciphertext):
        """
        Decrypt the given ciphertext using AES.
        """
        cipher = AES.new(self.sym_key, AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), self.block_size).decode()
        return plaintext

    def _hashes(self, encrypted_keyword):
        """
        Generate hash values for a given encrypted keyword to be used in the Bloom filter.
        """
        results = []
        for i in range(self.hash_count):
            digest = hashlib.sha256((encrypted_keyword + str(i)).encode()).hexdigest()
            results.append(int(digest, 16) % self.bloom_filter_size)
        return results

    def add_to_bloom_filter(self, keyword):
        """
        Add an encrypted keyword to the Bloom filter.
        """
        iv, encrypted_keyword = self.encrypt_symmetric(keyword)
        encrypted_keyword_str = encrypted_keyword.hex()
        for idx in self._hashes(encrypted_keyword_str):
            self.bloom_filter[idx] = 1

    def is_in_bloom_filter(self, encrypted_keyword_str):
        """
        Check if an encrypted keyword exists in the Bloom filter.
        """
        return all(self.bloom_filter[idx] for idx in self._hashes(encrypted_keyword_str))

    def index_file(self, filename, content):
        """
        Index the file's content by breaking it into phrases, encrypting them, and storing them in a Bloom filter.
        """
        print(f"Indexing file: {filename}")
        words = content.replace('\n', ' ').split()  # Replace line breaks with spaces
        indexed_phrases = set()
        for i in range(len(words)):
            for j in range(i + 1, min(i + 1 + self.max_phrase_length, len(words) + 1)):
                phrase = " ".join(words[i:j]).lower()
                phrase = ''.join(char for char in phrase if char.isalnum() or char.isspace())  # Remove punctuation
                if phrase not in indexed_phrases:
                    indexed_phrases.add(phrase)
                    iv, encrypted_phrase = self.encrypt_symmetric(phrase)
                    encrypted_phrase_str = encrypted_phrase.hex()
                    self.add_to_bloom_filter(phrase)
                    if encrypted_phrase_str not in self.phrase_to_files:
                        self.phrase_to_files[encrypted_phrase_str] = []
                    if filename not in self.phrase_to_files[encrypted_phrase_str]:
                        self.phrase_to_files[encrypted_phrase_str].append(filename)
                    print(f"Indexed encrypted phrase: '{encrypted_phrase_str}' in file: {filename}")

    def build_index(self, files):
        """
        Build the secure index from the provided files.
        """
        if not files:
            raise ValueError("No files provided for building the index.")
        for filename, content in files:
            self.index_file(filename, content)
        print("Index built successfully.")

    def search(self, query):
        """
        Search for a query in the index by first normalizing and encrypting the query.
        """
        query = query.lower()
        query = ''.join(char for char in query if char.isalnum() or char.isspace())  # Match normalization logic
        print(f"Searching for normalized query: '{query}'")
        try:
            iv, encrypted_query = self.encrypt_symmetric(query)
            encrypted_query_str = encrypted_query.hex()

            if self.is_in_bloom_filter(encrypted_query_str):
                print(f"DEBUG: Found in bloom filter (encrypted): '{encrypted_query_str}'")
                files = self.phrase_to_files.get(encrypted_query_str, [])
                return files
            else:
                print(f"DEBUG: Not found in bloom filter (encrypted): '{encrypted_query_str}'")
                return []
        except Exception as e:
            print(f"Error during search encryption: {e}")
            return []

if __name__ == "__main__":
    # Create the PrivacyPreservingSearch object
    pps = PrivacyPreservingSearch(sym_key_size=16, bloom_filter_size=1000, hash_count=3, max_phrase_length=5)

    # Step 1: Select files or a folder to upload
    print("Please select text files to upload.")
    root = Tk()
    root.withdraw()
    file_paths = filedialog.askopenfilenames(title="Select Text Files or Folder", filetypes=[("Text Files", "*.txt")])
    root.destroy()

    files = []
    for path in file_paths:
        try:
            with open(path, 'r', encoding='utf-8') as file:
                content = file.read().strip()
            if content:
                files.append((os.path.basename(path), content))
                print(f"Loaded file: {path}")
            else:
                print(f"Skipped empty file: {path}")
        except Exception as e:
            print(f"Error reading file {path}: {e}")

    # Step 2: Build the secure index
    if files:
        try:
            print("\nBuilding secure index...")
            pps.build_index(files)
        except Exception as e:
            print(f"Error during index building: {e}")
    else:
        print("\nNo valid files were provided.")  

    # Step 3: Search for a phrase
    while True:
        query = input("\nEnter your search phrase (or type 'exit' to quit): ").strip()
        if query.lower() == "exit":
            break
        print(f"\nSearching for: '{query}'")
        try:
            search_results = pps.search(query)
            if search_results:
                print(f"Phrase '{query}' found in file(s): {', '.join(search_results)}")
            else:
                print(f"Phrase '{query}' not found.")
        except Exception as e:
            print(f"Error during search: {e}")
