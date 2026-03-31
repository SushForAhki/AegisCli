# AegisCLI

AegisCLI, Python ile geliştirilmiş profesyonel, tek dosyalı ve konsol tabanlı bir siber güvenlik aracıdır.

Bu proje; eğitim, savunma odaklı analiz, log inceleme, pasif bilgi toplama ve temel altyapı doğrulama işlemleri için tasarlanmıştır. Tüm yapı tek bir Python dosyasında tutulurken, kod tarafında modüler bir mimari korunur.

## Gelistirici

- GitHub: `SushForAhki`

## Ozellikler

- `colorama` ile renkli CLI arayüzü
- Tek dosyalı Python mimarisi
- JSON rapor kaydı
- Web güvenlik tarama araçları
- Thread destekli port tarama
- Log analiz sistemi
- DNS ve ağ yardımcı araçları
- TLS sertifika inceleme
- Dosya ve metin hash üretimi
- Şifre gücü analizi
- Pasif OSINT araçları

## Moduller

### 1. Web Guvenlik Tarayicisi

- Güvenlik header taraması
- Endpoint keşfi
- Temel yansıma ve response davranış analizi

### 2. Port Tarayici

- Hızlı TCP port taraması
- Ayarlanabilir timeout
- `ThreadPoolExecutor` ile paralel tarama
- Basit banner grabbing desteği

### 3. Log Analizoru

- Büyük dosyalarda çalışmaya uygun yapı
- Regex tabanlı anahtar kelime sayımı
- Özet sonuçlar ve örnek eşleşme satırları

### 4. Ag ve DNS Araclari

- DNS/IP çözümleme
- Reverse DNS sorgusu

### 5. TLS Sertifika Analizi

- Sertifika subject ve issuer bilgileri
- Geçerlilik başlangıç/bitiş tarihi
- Kalan gün bilgisi

### 6. Hash Araci

- Metin hash üretimi
- Dosya hash üretimi
- `MD5`, `SHA1`, `SHA256` desteği

### 7. Sifre Gucu Test Araci

- Şifre karmaşıklık kontrolleri
- Yaygın şifre uyarıları
- Skor ve güç seviyesi çıktısı
- Güvenlik politikası önerileri

### 8. Pasif OSINT Araci

- Hedef profil özeti
- `robots.txt` ve `security.txt` kontrolü
- Temel sayfa meta verisi analizi

## Gereksinimler

- Python 3.10+
- `requests`
- `colorama`

Bağımlılıkları kurmak için:

```bash
pip install -r requirements.txt
```

## Kullanim

Aracı çalıştırmak için:

```bash
git clone https://github.com/SushForAhki/AegisCli.git
cd AegisCli
python Aegis.py
```

Program açıldığında ana menü üzerinden istediğin modülü seçerek kullanabilirsin.

## Cikti ve Raporlama

AegisCLI, analiz ve tarama sonuçlarını JSON formatında kaydeder:

```text
report_YYYYMMDD_HHMMSS.json
```

Aynı oturum içinde yapılan birden fazla işlem aynı rapor dosyasında tutulur.

## Proje Yapisi

Proje bilinçli olarak tek dosyalı bir yapı kullanır:

```text
main.py
requirements.txt
README.md
```

Kodun tamamı tek dosyada olsa da, içeride sınıf ve yardımcı fonksiyon yapıları ile düzenli şekilde organize edilmiştir.

## Kullanim Amaci

Bu araç şu amaçlar için uygundur:

- siber güvenlik eğitimi
- savunma odaklı analiz
- yetkili iç testler
- laboratuvar ve eğitim ortamları

Yetkisiz sistemler, ağlar veya web siteleri üzerinde kullanılmamalıdır.

## Notlar

- Proje exploit kodu içermez, analiz odaklıdır.
- Bazı modüller hedef sistemin erişilebilirliğine ve ağ durumuna bağlı olarak farklı sonuçlar verebilir.
- TLS, DNS ve HTTP tabanlı kontroller; hedef sistem istekleri engelliyorsa veya servis dışarıya açık değilse başarısız olabilir.

## Lisans

# geliştirici notu: Bu Yazılım ücretsiz Olarak Kullanıma Açılmıştır Bu Yazılıma Herhangibi Bir Modifiye Yapılabilir Veya Değiştirilebilir Ana Kaynak Reposu Bu Hesaptadır
