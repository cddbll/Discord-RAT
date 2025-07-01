# README.md (Türkçe)

> **UYARI:** Bu proje sadece eğitim ve araştırma amaçlı hazırlanmıştır. Bunu kendi sorumluluğunuzda ve yasalara uygun şekilde kullanınız.

---

## Proje Hakkında

Bu Discord botu, çeşitli sistem komutlarını ve dosya şifreleme işlemlerini yapabilen bir örnek projedir.  
Bot, dosya şifreleme, işlem yönetimi, pano içerik görüntüleme, ekran görüntüsü alma, komut çalıştırma gibi fonksiyonları barındırmaktadır.

---

## Özellikler

- Sistem genelinde dosya şifreleme (AES CBC mode)
- Dosya yükleme ve Defender hariç tutma ekleme
- Başlangıca gizli şekilde otomatik ekleme
- Pano (clipboard) içeriğini okuma ve gönderme
- Çalışan işlemleri listeleme ve sonlandırma
- Komut satırı komutu çalıştırma
- Sistem bilgilerini alma (IP, RAM, Disk, OS)
- Ekran görüntüsü alma
- Web sitesi açma
- Ekranda mesaj kutusu gösterme

---

## Kurulum

1. Python 3.8 veya üstü yüklü olmalı.
2. Gereken paketleri yükleyin:

pip install -r requirements.txt

    TOKEN değişkenine Discord bot tokenınızı ekleyin.

    Botu çalıştırın:

python bot.py

Kullanım

Bot aktifken Discord sunucusunda komutlar:

    !crypt uzanti — Tüm dosyaları belirtilen uzantıyla şifreler.

    !upload — Dosya yükler ve Defender hariç tutma ekler.

    !startup — Botu Windows başlangıcına gizli ekler.

    !clipboard — Pano içeriğini gönderir.

    !tasklist — Çalışan işlemleri listeler.

    !taskkill isim — İsimle işlem sonlandırır.

    !cmd komut — Komut satırında komut çalıştırır.

    !pcinfo — Sistem bilgilerini gönderir.

    !screen — Ekran görüntüsü alır.

    !website url — Tarayıcıda URL açar.

    !message mesaj — Mesaj kutusu gösterir.

    !help — Komut listesini gösterir.

Uyarı

Bu proje eğitim amaçlıdır. Dosya şifreleme ve sistem komutları içermektedir. Yetkisiz kullanımı veya paylaşımı yasal sorumluluk doğurabilir.
Lisans

Bu proje MIT Lisansı ile lisanslanmıştır.


---

# README.md (English)


# Discord Bot - For Educational Purposes

> **WARNING:** This project is prepared solely for educational and research purposes. Use it responsibly and according to the law.

---

## About the Project

This Discord bot is an example project with various system commands and file encryption capabilities.  
It includes features like file encryption, process management, clipboard viewing, screenshot capturing, command execution, and more.

---

## Features

- System-wide file encryption (AES CBC mode)
- File uploading with Defender exclusion addition
- Hidden addition to Windows startup
- Clipboard content reading and sending
- Listing and killing processes
- Running shell commands
- Getting system info (IP, RAM, Disk, OS)
- Taking screenshots
- Opening websites
- Showing message boxes

---

## Installation

1. Requires Python 3.8 or above.
2. Install dependencies:


pip install -r requirements.txt

    Add your Discord bot token to the TOKEN variable.

    Run the bot:

python bot.py

Usage

Commands in Discord server while the bot is active:

    !crypt extension — Encrypt all files with the specified extension.

    !upload — Uploads a file and adds Defender exclusion.

    !startup — Adds the bot hidden to Windows startup.

    !clipboard — Sends clipboard content.

    !tasklist — Lists running processes.

    !taskkill name — Terminates process by name.

    !cmd command — Runs shell command.

    !pcinfo — Sends system info.

    !screen — Takes a screenshot.

    !website url — Opens URL in browser.

    !message text — Shows a message box.

    !help — Shows the command list.

Warning

This project is for educational purposes only. It involves file encryption and system commands. Unauthorized use or distribution may have legal consequences.
License

This project is licensed under the MIT License.
