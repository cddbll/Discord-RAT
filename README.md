# TR - Türkçe

# Discord Bot Projesi: Sistem Yönetim Aracı

## Proje Hakkında

Bu proje, Python programlama dili ve Discord API kullanılarak geliştirilmiş bir sistem yönetim botudur. Bot, uzaktan sistem yönetimi için çeşitli işlevler sunar ve Discord üzerinden komutlarla kontrol edilebilir.

## Önemli Uyarı

Bu proje yalnızca eğitim amaçlı olup, bilgi edinmek isteyenler için hazırlanmıştır. **Kullanıcılar kendi sorumluluklarında hareket etmelidirler.** Bu araç izinsiz sistemlere erişmek veya kötü niyetli amaçlarla kullanılmamalıdır. Yasa dışı kullanımlardan proje sahibi sorumlu tutulamaz.

## Kurulum Talimatları

### Gereksinimler
- Python 3.8 veya üzeri
- pip paket yöneticisi
- Windows işletim sistemi (bazı özellikler Windows'a özeldir)

### Adım Adım Kurulum

1. **Gerekli Paketlerin Yüklenmesi**:
   ```bash
   pip install discord.py requests psutil pyautogui opencv-python pyperclip mss cryptography pypiwin32
   ```

2. **Bot Token'inin Ayarlanması**:
   - `TOKEN = "INPUT_YOUR_DISCORD_TOKEN"` satırını kendi Discord bot token'inizle değiştirin.

3. **Botu Çalıştırma**:
   ```bash
   python bot.py
   ```

### PyInstaller ile EXE'ye Dönüştürme

Botu taşınabilir bir Windows uygulamasına dönüştürmek için:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --icon=app.ico bot.py
```

Bu komut `dist` klasöründe tek bir çalıştırılabilir dosya oluşturacaktır.

## Çalışma Mantığı

Bot, Discord'un mesajlaşma API'sini kullanarak komutları dinler ve karşılık verir. Her komut belirli bir sistem işlemini tetikler:

1. **Komut Algılama**: Bot `!` prefix'i ile başlayan mesajları komut olarak algılar
2. **İşlem Yürütme**: Komuta karşılık gelen fonksiyon çalıştırılır
3. **Sonuç Paylaşma**: İşlem sonuçları Discord kanalına gönderilir

## Özellikler

**!help** - Botun kullanabileceğiniz tüm komutlarını ve ne işe yaradıklarını listeler. Yeni başlayanlar için temel rehber niteliğindedir.

**!getcam** - Bilgisayara bağlı olan kameraları tespit eder ve her birinden görüntü alıp size gönderir. Kameraların teknik özelliklerini (çözünürlük, fps) listeler.

**!token** - Sistemde kayıtlı olan Discord token'larını arar ve bulursa bu token'ların sahibi olan hesapların detaylı bilgilerini (kullanıcı adı, email, telefon) gösterir.

**!upload** - Discord'dan bir dosya indirip hedef bilgisayara kaydeder. Dosyayı gizler ve antivirüslerden korumaya çalışır. Genellikle ek komut dosyaları yüklemek için kullanılır.

**!startup** - Botu bilgisayar her açıldığında otomatik çalışacak şekilde ayarlar. Hem başlangıç klasörüne hem de Windows kayıt defterine ekleyerek kalıcılık sağlar.

**!clipboard** - O anda panoda (clipboard) bulunan içeriği okur ve size gösterir. Metinleri direkt iletebilirken, görselleri resim dosyası olarak paylaşır.

**!blockinput** - Klavye ve fare girişini tamamen engelleyerek kullanıcının bilgisayarla etkileşimini keser. Acil durum kilitleme için kullanışlıdır.

**!unblockinput** - !blockinput komutuyla engellenen kullanıcı girişlerini tekrar aktif hale getirir. Normal kullanıma dönmek için gereklidir.

**!inputstatus** - Girişlerin (klavye/fare) o anda engelli olup olmadığını gösteren basit bir durum raporu sunar.

**!uacbypass** - Windows'un UAC (Kullanıcı Hesabı Denetimi) güvenlik önlemini devre dışı bırakır veya yeniden etkinleştirir. Yönetici yetkisi gerektiren hassas bir komuttur.

**!enbtaskmngr** - Eğer engellenmişse Görev Yöneticisi'ni tekrar kullanılabilir hale getirir. Sistem sorunlarını gidermek için kullanışlıdır.

**!disbltaskmngr** - Görev Yöneticisi'ni devre dışı bırakır. Kullanıcıların işlemleri görmesini veya sonlandırmasını engeller.

**!taskkill** - Belirtilen işlemi (PID veya isimle) sonlandırır. "force" parametresiyle zorla kapatma seçeneği vardır. Sistem işlemlerini yönetmek için kullanılır.

**!tasklist** - O anda çalışan tüm işlemleri listeler. CPU ve bellek kullanım yüzdeleriyle birlikte detaylı bir sistem aktivite raporu sunar.

**!website** - Varsayılan tarayıcıda belirtilen web sitesini açar. URL'yi otomatik olarak https ile tamamlar.

**!cmd** - Windows komut isteminde (CMD) komut çalıştırır ve sonucunu gösterir. Sistem yönetimi için gelişmiş yetenekler sunar.

**!message** - Bilgisayarda anlık bir mesaj kutusu gösterir.

**!pcinfo** - Sistemin donanım özelliklerini, IP adresini ve konum bilgisini detaylı şekilde raporlar.

**!screen** - Anlık olarak masaüstünün ekran görüntüsünü alır ve Discord'a gönderir.

## Etik Kullanım Kılavuzu

Bu araç yalnızca:
- Kendi sisteminiz üzerinde test amaçlı
- Açıkça izin verilmiş sistemlerde
- Etik hackerlık eğitimi kapsamında
kullanılmalıdır.

## Son Notlar

Bu proje, sistem programlama ve güvenlik alanında bilgi edinmek isteyen geliştiriciler için hazırlanmıştır. Unutmayın ki bilgisayar sistemlerine izinsiz erişim yasaktır ve ciddi yasal sonuçları olabilir. Öğrenme sürecinizde daima etik kurallara uyun ve edindiğiniz bilgileri sorumluluk bilinciyle kullanın.

Discord: pqwok

--- --- --- ---
# EN - English

# Discord Bot Project: System Management Tool

## About the Project

This project is a system management bot developed using Python programming language and Discord API. The bot offers various functions for remote system management and can be controlled through Discord commands.

## Important Warning

This project is for educational purposes only, intended for those interested in ethical hacking and system security. **Users must act under their own responsibility.** This tool should not be used to access systems without permission or for malicious purposes. The project owner cannot be held responsible for illegal uses.

## Installation Instructions

### Requirements
- Python 3.8 or higher
- pip package manager
- Windows operating system (some features are Windows-specific)

### Step-by-Step Installation

1. **Install Required Packages**:
   ```bash
   pip install discord.py requests psutil pyautogui opencv-python pyperclip mss cryptography pypiwin32
   ```

2. **Set Bot Token**:
   - Replace `TOKEN = "INPUT_YOUR_DISCORD_TOKEN"` with your own Discord bot token

3. **Run the Bot**:
   ```bash
   python bot.py
   ```

### Convert to EXE with PyInstaller

To create a portable Windows application:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --icon=app.ico bot.py
```

This command will create a single executable file in the `dist` folder.

## How It Works

The bot listens for commands through Discord's messaging API and responds accordingly. Each command triggers specific system operations:

1. **Command Detection**: The bot recognizes messages starting with `!` as commands
2. **Execution**: The corresponding function for the command is executed
3. **Result Sharing**: Operation results are sent to the Discord channel

## Features

**!help** - Lists all available commands and their functions. Serves as a basic guide for beginners.

**!getcam** - Detects connected cameras and captures images from each. Lists technical specifications (resolution, fps) of cameras.

**!token** - Searches for registered Discord tokens in the system and displays detailed account information (username, email, phone) if found.

**!upload** - Downloads a file from Discord and saves it to the target computer. Hides the file and attempts to protect it from antivirus software. Typically used to upload additional script files.

**!startup** - Configures the bot to run automatically on system startup. Adds to both the startup folder and Windows registry for persistence.

**!clipboard** - Reads current clipboard contents and displays them. Shares text directly while sending images as files.

**!blockinput** - Completely blocks keyboard and mouse input, preventing user interaction. Useful for emergency lockdown.

**!unblockinput** - Re-enables user inputs blocked by !blockinput. Required to return to normal operation.

**!inputstatus** - Provides a simple status report showing whether inputs (keyboard/mouse) are currently blocked.

**!uacbypass** - Disables or re-enables Windows UAC (User Account Control) security measure. Requires administrator privileges.

**!enbtaskmngr** - Re-enables Task Manager if it was disabled. Useful for troubleshooting system issues.

**!disbltaskmngr** - Disables Task Manager. Prevents users from viewing or terminating processes.

**!taskkill** - Terminates specified processes (by PID or name). Includes "force" parameter for forced termination. Used for system process management.

**!tasklist** - Lists all currently running processes. Provides detailed system activity report with CPU and memory usage percentages.

**!website** - Opens specified website in default browser. Automatically completes URLs with https.

**!cmd** - Executes commands in Windows Command Prompt (CMD) and displays results. Offers advanced capabilities for system management.

**!message** - Displays a popup message box on the computer.

**!pcinfo** - Provides detailed report of system hardware specifications, IP address, and location information.

**!screen** - Takes a screenshot of the desktop and sends it to Discord. Useful for remote monitoring.

## Ethical Usage Guide

This tool should only be used for:
- Testing on your own systems
- Systems with explicit permission
- Ethical hacking education purposes

## Final Notes

This project was created for developers interested in system programming and security. Remember that unauthorized access to computer systems is prohibited and may have serious legal consequences. Always follow ethical guidelines in your learning process and use acquired knowledge responsibly.

The bot offers comprehensive system management capabilities through Discord, making it a powerful tool for remote administration when used ethically and responsibly.

Discord: pqwok
