import os
import shutil
import threading
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_FOLDER = r"C:\Users\harsh\Downloads"

# ✅ Added "💾 Applications" for installers, disc images & APKs
FILE_TYPES = {
    "📸 Images": [".jpg", ".jpeg", ".png", ".gif", ".bmp"],
    "📄 Documents": [".pdf", ".docx", ".txt", ".xlsx", ".pptx", ".zip", ".rar", ".tar"],  # Archives in Documents
    "🎥 Videos": [".mp4", ".mkv", ".avi"],
    "🎵 Music": [".mp3", ".wav"],
    "💾 Applications": [".exe", ".msi", ".iso", ".dmg", ".apk"],  # NEW CATEGORY 🚀
}

if not os.path.exists(WATCH_FOLDER):
    print("🚨 Uh-oh! Folder not found! Please check the path and try again. Exiting... ❌")
    exit()

def organize_files(latest_file=None):
    """Organize a single detected file or all files if no file is specified."""
    files = [latest_file] if latest_file else os.listdir(WATCH_FOLDER)
    
    for file in files:
        file_path = os.path.join(WATCH_FOLDER, file)
        if os.path.isfile(file_path):
            move_file(file_path, file)

def move_file(file_path, file_name):
    """Move a file to its respective folder."""
    ext = os.path.splitext(file_name)[1].lower()
    for folder, extensions in FILE_TYPES.items():
        if ext in extensions:
            target_folder = os.path.join(WATCH_FOLDER, folder.replace("📸 ", "").replace("📄 ", "").replace("🎥 ", "").replace("🎵 ", "").replace("💾 ", ""))
            os.makedirs(target_folder, exist_ok=True)
            new_path = os.path.join(target_folder, file_name)

            if os.path.exists(new_path):
                base, ext = os.path.splitext(file_name)
                new_file_name = f"{base}_copy{ext}"
                new_path = os.path.join(target_folder, new_file_name)

            shutil.move(file_path, new_path)
            print(f"✅ BOOM! {file_name} teleported to {folder}! 🚀")
            return  

class FileOrganizerHandler(FileSystemEventHandler):
    """Detects new and modified files, ensuring only one event per detection."""
    def on_modified(self, event):
        if not event.is_directory:
            latest_file = os.path.basename(event.src_path)
            print("🔄 A file was modified... Organizing it now! 🧹")
            organize_files(latest_file)

    def on_created(self, event):
        if not event.is_directory:
            latest_file = os.path.basename(event.src_path)
            print(f"🆕 NEW FILE ALERT! {latest_file} just arrived! 📦 Sorting it now... 🎯")
            organize_files(latest_file)

def start_monitoring():
    """Starts monitoring the folder for changes."""
    print(f"👀 Watching over {WATCH_FOLDER} like a hawk! 🦅")
    event_handler = FileOrganizerHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_FOLDER, recursive=True)

    observer_thread = threading.Thread(target=observer.start, daemon=True)
    observer_thread.start()
    return observer, observer_thread

def stop_command(observer):
    """Listens for 'stop' command to gracefully exit the script."""
    while True:
        command = input().strip().lower()
        if command == "stop":
            print("\n🛑 WHOA! You hit the brakes! Stopping organizer... ⚡")
            observer.stop()
            observer.join()
            print("💤 The File Organizer has gone to sleep. See ya later! 💤")
            exit()

if __name__ == "__main__":
    print("🎉 Welcome to the *Ultimate File Organizer Bot*! 🤖✨")
    print("💪 Let’s clean up this folder like a pro! 🧹🔥")

    observer, observer_thread = start_monitoring()

    stop_thread = threading.Thread(target=stop_command, args=(observer,), daemon=True)
    stop_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 WHOA! You hit the brakes! Stopping organizer... ⚡")
        observer.stop()
        observer_thread.join()
