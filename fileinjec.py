
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk
import os
import random
import time
import codecs
from encrypted import PrivacyPreservingSearch

class PrivacyPreservingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Privacy-Preserving Search System")
        self.root.geometry("600x400")
        self.root.configure(bg="#2e3b4e")
        
        self.pps = PrivacyPreservingSearch(sym_key_size=16, bloom_filter_size=1000, hash_count=3, max_phrase_length=5)
        self.search_timestamps = {}
        
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Arial", 12, "bold"), padding=5)
        style.configure("TLabel", font=("Arial", 10), background="#2e3b4e", foreground="white")
        
        self.setup_ui()
    
    def setup_ui(self):
        ttk.Label(self.root, text="Privacy-Preserving Search System", font=("Helvetica", 16, "bold")).pack(pady=10)
        upload_btn = ttk.Button(self.root, text="Upload Files", command=self.upload_files)
        upload_btn.pack(pady=10)
        build_btn = ttk.Button(self.root, text="Build Index", command=self.build_index)
        build_btn.pack(pady=10)
        
        ttk.Label(self.root, text="Enter Search Phrase:", anchor="w").pack(fill="x", padx=20)
        self.search_entry = ttk.Entry(self.root, width=40)
        self.search_entry.pack(pady=5)
        
        search_btn = ttk.Button(self.root, text="Search", command=self.search_phrase)
        search_btn.pack(pady=5)
        
        self.results_box = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=60, height=10, bg="#f0f0f0")
        self.results_box.pack(pady=10)
        
        self.status_label = ttk.Label(self.root, text="Status: Ready", anchor="center")
        self.status_label.pack(pady=5)
    
    def is_valid_text_file(self, file_path):
        suspicious_keywords = ["<script>", "eval(", "exec", "import os", "subprocess"]
        max_size = 5 * 1024 * 1024
        
        if os.path.getsize(file_path) > max_size:
            return False, "File too large"
        
        try:
            with codecs.open(file_path, 'r', encoding='utf-8', errors='strict') as file:
                content = file.read()
                if any(keyword in content for keyword in suspicious_keywords):
                    return False, "Suspicious content detected"
        except UnicodeDecodeError:
            return False, "Invalid encoding"
        
        return True, "Valid file"
    
    def upload_files(self):
        files = filedialog.askopenfilenames(title="Select Text Files", filetypes=[("Text Files", "*.txt")])
        if not files:
            messagebox.showwarning("No Files Selected", "Please select files to upload.")
            return
        
        self.files = []
        for file_path in files:
            valid, reason = self.is_valid_text_file(file_path)
            if valid:
                with open(file_path, 'r', encoding='utf-8') as file:
                    self.files.append((file_path, file.read().strip()))
            else:
                messagebox.showwarning("Invalid File", f"{file_path} was rejected: {reason}")
        
        if self.files:
            messagebox.showinfo("Files Uploaded", f"{len(self.files)} file(s) uploaded successfully.")
    
    def refresh_encryption_key(self):
        self.pps = PrivacyPreservingSearch(sym_key_size=16, bloom_filter_size=1000, hash_count=3, max_phrase_length=5)
    
    def build_index(self): 
        if not hasattr(self, 'files') or not self.files:
            messagebox.showwarning("No Files", "Please upload files before building the index.")
            return
        
        self.refresh_encryption_key()
        
        try:
            self.pps.build_index(self.files)
            self.status_label.config(text="Status: Index Built Successfully", foreground="blue")
            messagebox.showinfo("Index Built", "Index was built successfully!")
        except Exception as e:
            messagebox.showerror("Index Error", f"Error during index building: {e}")
    
    def search_phrase(self):
        query = self.search_entry.get().strip()
        if not query:
            messagebox.showwarning("Empty Query", "Please enter a phrase to search.")
            return

        current_time = time.time()
        if query in self.search_timestamps and current_time - self.search_timestamps[query] < 5:
            messagebox.showwarning("Rate Limited", "Please wait before making another query.")
            return

        self.search_timestamps[query] = current_time

        try:
            results = self.pps.search(query)

            # Generate realistic false positives
            misleading_paths = [
                f"/backup/doc{random.randint(1, 99)}.txt",
                f"/archive/log{random.randint(1, 99)}.txt",
                f"/temp/storage{random.randint(1, 99)}.txt",
                f"/misc/dataset{random.randint(1, 99)}.txt",
                f"/old_versions/report{random.randint(1, 99)}.txt",
                f"/system_logs/error{random.randint(1, 99)}.txt",
                f"/unused/documents{random.randint(1, 99)}.txt"
            ]

            fake_results = random.sample(misleading_paths, k=random.randint(1, 3)) if random.random() > 0.5 else []
            results += fake_results

            random.shuffle(results)

            self.results_box.delete(1.0, tk.END)
            if results:
                self.results_box.insert(tk.END, f"Phrase found in:\n" + "\n".join(results))
                self.status_label.config(text="Status: Search Completed", foreground="blue")
            else:
                self.results_box.insert(tk.END, "Phrase not found in any files.")
                self.status_label.config(text="Status: No Results Found", foreground="red")
        except Exception as e:
            messagebox.showerror("Search Error", f"Error during search: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PrivacyPreservingApp(root)
    root.mainloop()
