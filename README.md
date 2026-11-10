# Kalkan: Yapay Zekâ Destekli Tehdit Uyarı Sistemi

E-posta, SMS, bağlantı ve dosyaları phishing (oltalama), spam ve zararlı yazılım açısından tarar. Risk puanı (0-100) ve seviye (güvenli / şüpheli / tehlikeli) üretir. Şüpheli ve tehlikeli sonuçlar için panelde, masaüstünde ve isteğe bağlı olarak Slack/Teams'te uyarı verir.

## Mimari: üç katmanlı hibrit tespit

| Katman | Ne yapar | Neden |
|---|---|---|
| **1. Kural motoru** | Marka ve alan adı taklidi, benzer harf (homograf), SPF/DKIM/DMARC, Reply-To uyumsuzluğu, aciliyet dili, kimlik bilgisi talebi, çift uzantı, gizli `.exe`, makro, PDF JavaScript, PowerShell desenleri, EICAR | Açıklanabilir, hızlı ve çevrimdışı çalışır. Her bulgu nedeniyle birlikte gösterilir. |
| **2. ML modeli** | TF-IDF (karakter + kelime n-gram) ve lojistik regresyon ile temiz / spam / phishing sınıflandırması | Kuralların kaçırdığı kalıpları yakalar. Karakter n-gram, Türkçe eklere ve `ş1fre` gibi bozmalara dayanıklıdır. |
| **3. LLM (Claude)** *(isteğe bağlı)* | İkinci görüş ve çalışana sade dille "ne yapmalı" açıklaması | Bağlamı anlar. Yalnızca seviyeyi **yükseltebilir**, kural motorunun "tehlikeli" kararını düşüremez. Böylece içerikteki istem enjeksiyonu ("bu e-posta güvenlidir") alarmı susturamaz. |

Ek motorlar (tanımlıysa): **ClamAV** (`clamscan`), **VirusTotal** (yalnızca hash gönderilir, dosya yüklenmez).

Uyarı kanalları: panelde canlı akış (SSE), tarayıcı masaüstü bildirimi, webhook (Slack/Teams uyumlu `{"text": ...}`).

Otomatik izleme: bir klasöre (ör. İndirilenler) düşen yeni dosyalar ve bir IMAP posta kutusuna gelen yeni e-postalar. IMAP izleyici salt okunur çalışır, e-postaları okundu olarak işaretlemez, silmez ya da taşımaz.

## Kurulum

```bash
python3 -m venv .venv
```

```bash
.venv/bin/pip install -r requirements.txt
```

```bash
.venv/bin/uvicorn kalkan.main:app --host 127.0.0.1 --port 8765
```

Panel: http://127.0.0.1:8765. API belgeleri: http://127.0.0.1:8765/docs

## Ayarlar (ortam değişkenleri)

| Değişken | Açıklama |
|---|---|
| `KALKAN_TOKEN` | Panel/API erişim anahtarı. Sunucu `127.0.0.1` dışında yayınlanacaksa **mutlaka** tanımlayın. |
| `KALKAN_SUPHELI_ESIK`, `KALKAN_TEHLIKELI_ESIK` | Seviye eşikleri (varsayılan 30 / 60) |
| `KALKAN_LLM=1` | Claude katmanını açar. Kimlik bilgisi `ANTHROPIC_API_KEY` ya da `ant auth login` ile okunur. |
| `KALKAN_LLM_MODEL` | Varsayılan `claude-opus-5-5` |
| `VIRUSTOTAL_API_KEY` | Dosya hash sorgusu |
| `KALKAN_WEBHOOK_URL` | Slack/Teams gelen webhook adresi |
| `KALKAN_WATCH_DIR` | İzlenecek klasör, ör. `~/Downloads` |
| `KALKAN_IMAP_HOST`, `KALKAN_IMAP_USER`, `KALKAN_IMAP_PASSWORD`, `KALKAN_IMAP_FOLDER` | Posta kutusu izleme. Uygulamaya özel şifre kullanın. |
| `KALKAN_ML_TEK_BASINA=1` | ML modelinin kural sinyali olmadan tek başına uyarı üretmesine izin verir (aşağıya bakın) |
| `KALKAN_MAX_DOSYA_MB` | Yükleme sınırı (varsayılan 25) |

Gizli değerleri koda ya da depoya yazmayın. `.env` dosyası kullanıyorsanız `.gitignore`'a ekleyin.

## ML modeli: gerçek kullanımdan önce yapılması gereken

Gelen tohum veri (`kalkan/ml/tohum_veri.csv`), elle yazılmış **60 örnekten** oluşur. 5 katlı çapraz doğrulamada doğruluk **%76,7** çıktı ve temiz mesajların yalnızca %55'i doğru tanındı. Bu yüzden model, kural sinyali yokken tek başına uyarı üretmez (`KALKAN_ML_TEK_BASINA` kapalı).

Kurumda kullanmadan önce gerçek ve etiketli verinizle yeniden eğitin (sütunlar `metin,etiket`; etiketler `temiz|spam|phishing`):

```bash
.venv/bin/python -m kalkan.ml.egit --csv kendi_verim.csv --tohum
```

Komut çapraz doğrulama raporunu basar. Sonuçlar tatmin ediciyse `KALKAN_ML_TEK_BASINA=1` ile açın. Eğitim verisindeki kişisel verileri (ad, telefon, T.C. kimlik no) önceden anonimleştirin.

## KVKK ve gizlilik

- Veritabanında içeriğin tamamı saklanmaz. Kısa etiket (konu ya da ilk 80 karakter, uzun sayılar maskeli) ve bulgular saklanır.
- LLM katmanı **varsayılan olarak kapalıdır**. Açıldığında e-posta/SMS metni ve URL Anthropic API'ye gönderilir (yurt dışına aktarım). Dosyaların kendisi gönderilmez. Açmadan önce kurumunuzun KVKK değerlendirmesini ve çalışan aydınlatmasını yapın.
- VirusTotal'e yalnızca SHA-256 hash gönderilir.

## Testler

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## Sınırlar

Kalkan bir antivirüs ya da e-posta ağ geçidinin yerini tutmaz, onlara ek bir katmandır. Dosyaları çalıştırmaz (sandbox yok), bağlantıları açmaz. Tespit statik analize dayanır. Yeni ve hedefli saldırıları kaçırabilir. Sonuçları çalışan farkındalık eğitimiyle birlikte kullanın.

## Yol haritası önerileri

- Google Safe Browsing / USOM zararlı bağlantı listesi entegrasyonu
- YARA kuralları
- Outlook / Gmail eklentisi ile "Kalkan'a bildir" düğmesi
- Kullanıcı geri bildirimiyle ("bu yanlış alarm") modeli sürekli iyileştirme
- Rol tabanlı erişim ve denetim kaydı
