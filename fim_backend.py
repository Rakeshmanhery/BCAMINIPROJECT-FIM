import os
import hashlib
import time
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

SUSPICIOUS_EXTENSIONS = {'.locked', '.crypto', '.enc', '.ransom'}
MODIFICATION_LIMIT = 5
TIME_WINDOW_SECONDS = 2.0

class SecurityMonitorHandler(FileSystemEventHandler):
    def __init__(self, target_dir, ui_alert_callback, ui_log_callback):
        super().__init__()
        self.target_dir = target_dir
        self.trigger_alert = ui_alert_callback
        self.log_event = ui_log_callback
        self.file_hashes = {}
        self.modification_timestamps = deque()
        self.is_isolated = False
        
        self.generate_baseline()

    def calculate_sha256(self, filepath):
        """Generates cryptographic SHA-256 hash value to verify integrity."""
        # Small delay to allow the OS to release its write lock on the file
        time.sleep(0.1) 
        hash_sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except (PermissionError, FileNotFoundError):
            return None

    def generate_baseline(self):
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                full_path = os.path.join(root, file)
                file_hash = self.calculate_sha256(full_path)
                if file_hash:
                    self.file_hashes[full_path] = file_hash

    def evaluate_behavioral_patterns(self, event_path):
        if self.is_isolated: return True
        current_time = time.time()
        self.modification_timestamps.append(current_time)

        while self.modification_timestamps and (current_time - self.modification_timestamps[0] > TIME_WINDOW_SECONDS):
            self.modification_timestamps.popleft()

        ext = os.path.splitext(event_path)[1].lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            self.is_isolated = True
            self.trigger_alert("Ransomware Signature Extension Detected", event_path)
            return True

        if len(self.modification_timestamps) >= MODIFICATION_LIMIT:
            self.is_isolated = True
            self.trigger_alert("High-Frequency Operations", f"{len(self.modification_timestamps)} edits within {TIME_WINDOW_SECONDS}s")
            return True
        return False

    def on_created(self, event):
        if event.is_directory or self.is_isolated: return
        # Ignore the temporary windows default creation string to avoid UI clutter
        if "New Text Document" in event.src_path: return
        
        new_hash = self.calculate_sha256(event.src_path)
        self.file_hashes[event.src_path] = new_hash
        self.log_event("CREATED", f"New file tracked: {os.path.basename(event.src_path)}")

    def on_moved(self, event):
        """Catches Windows file renaming events (e.g. from 'New Text Document' to your typed name)"""
        if event.is_directory or self.is_isolated: return
        
        # Calculate hash for the newly named file location
        new_hash = self.calculate_sha256(event.dest_path)
        if new_hash:
            self.file_hashes[event.dest_path] = new_hash
            # Clean up old temporary record if it existed
            if event.src_path in self.file_hashes:
                del self.file_hashes[event.src_path]
                
        self.log_event("RENAMED", f"{os.path.basename(event.src_path)} -> {os.path.basename(event.dest_path)}")

    def on_modified(self, event):
        if event.is_directory or self.is_isolated: return
        if "New Text Document" in event.src_path: return
        
        if self.evaluate_behavioral_patterns(event.src_path): return

        current_hash = self.calculate_sha256(event.src_path)
        old_hash = self.file_hashes.get(event.src_path)

        # If it's a completely un-tracked file modification, register its baseline now
        if current_hash and old_hash is None:
            self.file_hashes[event.src_path] = current_hash
            return

        if current_hash and old_hash and current_hash != old_hash:
            self.file_hashes[event.src_path] = current_hash
            self.log_event("MODIFIED", f"Hash Mismatch: {os.path.basename(event.src_path)}")

    def on_deleted(self, event):
        if event.is_directory or self.is_isolated: return
        if event.src_path in self.file_hashes: 
            del self.file_hashes[event.src_path]
        self.log_event("DELETED", f"File removed: {os.path.basename(event.src_path)}")