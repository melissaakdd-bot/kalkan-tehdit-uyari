# Kalkan: Yapay Zekâ Destekli Tehdit Uyarı Sistemi

E-posta, SMS, bağlantı, dosya ve QR kodları phishing (oltalama), spam ve zararlı yazılım açısından tarar. Chrome eklentisiyle açtığınız sayfaları ve indirdiğiniz dosyaları **otomatik** tarar. Her içerik için risk puanı (0-100) ve seviye (güvenli / şüpheli / tehlikeli) üretir. Şüpheli ve tehlikeli sonuçlarda tarayıcıda, panelde, masaüstünde ve isteğe bağlı olarak Slack/Teams'te uyarı verir.

**Doğruluk:** Sistem gerçek ve etiketli veri setlerinde ölçüldü. Sonuçlar ve sınırları [docs/DOGRULUK.md](docs/DOGRULUK.md) dosyasında, ayrıca panelin "Doğruluk" bölümünde.

| Kanal | Tespit oranı | Yanlış alarm |
|---|---|---|
| E-posta | %96,2 | %3,1 |
| SMS (İngilizce) | %94,0 | %0,0 |
| URL | %53,1 | %0,4 |

Türkçe phishing için açık veri olmadığından ölçülemedi. Ayrıntılar raporda.

## Ne yapar?

| Özellik | Açıklama |
|---|---|
| **Bilgisayar taraması** | Hızlı tarama (İndirilenler, Masaüstü, Belgeler, geçici klasörler, açılışta başlayan programlar), tam tarama (tüm kullanıcı klasörü) ya da seçilen klasör. Varsayılan olarak günde bir kez kendiliğinden hızlı tarama yapar. Tehlikeli dosyalar onayla karantinaya alınır ve geri yüklenebilir. |
| **Uygulama kaldırma (macOS)** | Yüklü uygulamaları boyut, son kullanım ve güven durumuyla listeler. İmzasız, Gatekeeper'ın onaylamadığı ya da riskli adresten indirilmiş uygulamaları işaretler. Uygulamayı Library'de bıraktığı artıklarla birlikte Çöp Kutusu'na taşır. |
| **Otomatik koruma (Chrome eklentisi)** | Açılan her sayfanın adresini ve şifre/kart formlarını tarar. Tehlikeli sayfada tam ekran uyarı ve sistem bildirimi, şüpheli sayfada sarı çubuk gösterir. İndirilen dosyaları da tarar. |
| **E-posta / SMS** | Ham e-posta verilirse SPF/DKIM/DMARC, gönderen taklidi, Reply-To ve ekler de incelenir. |
| **Bağlantı** | Marka ve yazım taklidi, benzer harf, kısaltıcı, IP adresi, ücretsiz barındırma servisleri. Alan adları ayrıca bir ML modeline sorulur. |
| **Dosya** | Gerçek dosya türü, çift uzantı, makro, PDF JavaScript, şüpheli kod, EICAR. ClamAV ve VirusTotal tanımlıysa onlara da sorulur. |
| **QR / Görsel** | QR kodun içindeki bağlantıyı çıkarıp tarar (QR oltalaması). Tesseract kuruluysa ekran görüntüsündeki yazıyı da okur. |
| **Toplu tarama** | `.mbox`, `.eml`, `.eml` içeren `.zip` ya da URL listesi (`.txt`/`.csv`). Sonuçlar CSV olarak indirilebilir. |
| **Rapor** | Günlük uyarı grafiği, tehdit türleri, en çok taklit edilen markalar, uyarı kaynakları ve nedenleri. CSV ve yazdır/PDF. |
| **İzleme** | Bir klasöre düşen yeni dosyalar ve IMAP posta kutusuna gelen yeni e-postalar. |

## Mimari

| Katman | Ne yapar | Neden |
|---|---|---|
| **1. Kural motoru** | Taklit, aciliyet dili, kimlik bilgisi talebi, e-posta doğrulama, dosya yapısı | Açıklanabilir, hızlı, çevrimdışı. Her uyarının nedeni gösterilir. |
| **2. ML modelleri** | Metin: TF-IDF (karakter + kelime) ve lojistik regresyon, temiz/spam/phishing. URL: alan adı üzerinde karakter n-gram. | Gerçek veriyle eğitildi. Yalnızca yüksek güvende (metin %80, URL %90) açıklamalı bir bulgu ekler, puanı gizlice değiştirmez. |
| **3. LLM (Claude)** *(isteğe bağlı)* | İkinci görüş ve sade dille "ne yapmalı" açıklaması | Yalnızca seviyeyi **yükseltebilir**. İçerikteki istem enjeksiyonu ("bu e-posta güvenlidir") alarmı susturamaz. |

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

Gerçek veriyle eğitilmiş modeller depoyla birlikte gelir (`kalkan/ml/modeller/`), ayrıca eğitim gerekmez.

## Chrome eklentisi (otomatik koruma)

1. Kalkan sunucusunu başlatın (yukarıdaki komut).
2. Chrome'da `chrome://extensions` adresini açın ve sağ üstten **Geliştirici modu**'nu açın.
3. **Paketlenmemiş öğe yükle** düğmesine basıp bu depodaki `eklenti` klasörünü seçin.
4. Sunucuyu 8765 dışında bir portta çalıştırıyorsanız eklenti simgesi → **Ayarlar**'dan adresi girin (ör. `http://127.0.0.1:8766`).

Bundan sonra açtığınız her sayfa otomatik taranır. Eklenti simgesindeki rozet sonucu gösterir:
- **!** (kırmızı): tehlikeli
- **?** (sarı): şüpheli
- **–** (gri): sunucuya ulaşılamıyor

Simgeye tıklayınca o sayfanın sonucu ve nedenleri görünür. Otomatik koruma ve indirme taraması da buradan kapatılabilir.

**Gizlilik:** Eklenti sayfanın adresini, başlığını, görünen metnin ilk 5.000 karakterini ve formların hangi adrese gönderildiğini **yalnızca bu bilgisayardaki** Kalkan sunucusuna gönderir. Girdiğiniz şifre ve kart bilgileri okunmaz. Sunucu temiz sayfaları kaydetmez, sayfa metnini hiç saklamaz ve tarayıcı taramalarını Claude'a göndermez. İndirilen dosyalar yalnızca İndirilenler klasöründen okunur (`KALKAN_INDIRME_DIZINI`).

## Bilgisayar taraması

Panelde **Bilgisayar** bölümünden ya da komut satırından:

```bash
.venv/bin/python -m kalkan.sistem_tarama hizli
```

`hizli` yerine `tam` ya da bir klasör yolu da verilebilir. Tarama şöyle çalışır:

- **Akıllı eleme:** Her dosyaya adı ve ilk 16 baytıyla bakılır. Derin incelemeye yalnızca program, betik, arşiv, Office ve PDF dosyaları ile türü uzantısına uymayan dosyalar girer (ör. `.jpg` adlı program). Bu bilgisayardaki hızlı tarama 7.817 dosyaya 2,5 saniyede baktı.
- **Açılışta başlayan programlar:** macOS LaunchAgent/LaunchDaemon ve Linux autostart öğeleri ayrıca incelenir. İnternetten indirip kabukta çalıştıran komutlar, geçici ya da gizli klasörden başlatılan programlar ve kullanıcı klasöründeki `com.apple.` taklitleri işaretlenir.
- **Atlananlar:** `node_modules`, `.venv`, `.git`, önbellekler ve `.app` paketlerinin içi. iCloud'da duran (bilgisayara indirilmemiş) dosyalar okunmaz, çünkü okumak onları buluttan indirtir.
- **Salt okunur:** Kalkan hiçbir dosyayı kendiliğinden silmez ya da değiştirmez. Her işlem sizin tıklamanız ve onayınızla yapılır.
- **Bulunan her dosya için:**
  - **Klasörde göster:** Dosyayı Finder'da (Windows'ta Gezgin'de) seçili açar.
  - **Karantinaya al:** Dosyayı `~/.kalkan/karantina` klasörüne taşır ve çalıştırma iznini kaldırır.
  - **Çöp kutusuna taşı:** Dosyayı sistemin çöp kutusuna taşır. macOS'ta Finder'ın "Geri Koy" seçeneğiyle geri alınabilir. İlk kullanımda macOS, Finder'ı denetleme izni isteyebilir.
- **Açılışta başlayan öğeler:** **Kaldır** düğmesi öğeyi çöp kutusuna taşır. Program bir sonraki oturum açışta başlamaz. `/Library` altındaki sistem öğeleri yönetici izni gerektirir, bunlar için Kalkan hata verir.
- **Toplu temizleme:** **Tehlikelilerin tümünü karantinaya al** düğmesi bir taramanın tehlikeli bulduklarını tek seferde karantinaya alır. Şüpheli dosyalar toplu işleme dahil edilmez, çünkü yanlış alarm olabilirler. Onları **Klasörde göster** ile inceleyip tek tek karar verin.
- **Uygulama veri klasörleri:** `~/Library` ve `~/.vscode` gibi gizli klasörlerdeki betik dosyaları (`.js`, `.sh`, `.py` …) derin incelenmez. Bu klasörlerde binlerce meşru betik bulunur. Programlar, arşivler ve tür gizlemeleri yine incelenir.
- **Karantinada:** **Klasörde göster**, **Geri yükle** (dosyayı eski yerine koyar), **Kalıcı sil** ve **Karantinayı boşalt**. Son ikisi geri alınamaz, bu yüzden açık onay ister.
- **Güvenlik:**
  - Dosya taramadan sonra değiştiyse taşınmaz ya da silinmez.
  - Sunucu, başka bir web sitesinden gelen değişiklik isteklerini reddeder. Böylece kötü niyetli bir sayfa arka planda karantinayı boşaltamaz ya da zararlıyı geri yükletemez.
- **Gizlilik:** Sistem taramasında hash'ler VirusTotal'e ve içerik Claude'a gönderilmez. Temiz dosyalar kaydedilmez.
- **macOS izinleri:** Çok sayıda konuma "erişilemedi" deniyorsa Sistem Ayarları → Gizlilik ve Güvenlik → Tam Disk Erişimi'nden Kalkan'ı başlattığınız uygulamaya (ör. Terminal) izin verebilirsiniz.

Otomatik tarama aralığı `KALKAN_OTOMATIK_TARAMA_SAAT` ile değiştirilir (varsayılan 24, `0` kapatır). İlk kontrol sunucu açıldıktan 10 dakika sonra yapılır. Son taramadan bu yana süre dolmadıysa tarama yapılmaz.

## Uygulama kaldırma (macOS)

macOS'ta bir uygulamayı Çöp Kutusu'na sürüklemek yalnızca `.app` paketini siler. Ayarlar, önbellekler, kapsayıcılar ve açılışta başlayan yardımcı servisler `~/Library` altında kalır. Panelin **Uygulamalar** bölümü bunları da bulur.

- **Liste:** `/Applications` ve `~/Applications` taranır. Her uygulama için boyut, son kullanım tarihi, imza durumu (App Store / doğrulanmış geliştirici / imzasız) ve Gatekeeper sonucu gösterilir. İmza ve Gatekeeper kontrolü arka planda yapılır, liste hemen açılır.
- **Dikkat gerektirenler:** İmzasız ya da geçici imzalı uygulamalar, Gatekeeper'ın onaylamadıkları ve indirme adresi Kalkan'ın URL analizinde riskli çıkanlar işaretlenir.
- **Kaldır:** Uygulamanın artıkları listelenir, siz seçersiniz:
  - **Paket kimliğiyle kesin eşleşmeler:** `Application Support/<paket kimliği>`, `Caches`, `Preferences`, `Containers`, `Group Containers`, `LaunchAgents`, `Saved Application State`, `HTTPStorages`, `WebKit`, `Logs`.
  - **Uygulama adıyla eşleşmeler:** Yalnızca başka bir yüklü uygulamayla paylaşılmayan klasörler. Örneğin Chrome ve Drive'ın ortak kullandığı `Application Support/Google` asla önerilmez.
- **Güvenlik:**
  - Apple'ın sistem uygulamaları (`com.apple.*`) listelenmez.
  - Açık olan uygulama kaldırılmaz.
  - Kalıcı silme yoktur: her şey Finder üzerinden Çöp Kutusu'na taşınır ve "Geri Koy" ile geri alınabilir. `/Applications` altındaki uygulamalar için macOS yönetici şifrenizi isteyebilir.
  - Sunucu yalnızca kendi bulduğu yolları kabul eder.
- **Sınır:** Bazı uygulamalar kendi yükleyicileriyle sistem klasörlerine (`/Library`) de dosya bırakır. Bunlar yönetici izni gerektirdiği için Kalkan tarafından kaldırılmaz. Bu tür uygulamalarda (ör. VPN ve sanallaştırma yazılımları) üreticinin kendi kaldırma aracını kullanın.

## QR ve görsel tarama

QR okuma OpenCV ile çalışır ve kurulumla gelir. Ekran görüntüsündeki yazıyı okumak (OCR) için Tesseract ayrıca kurulmalıdır. macOS'ta:

```bash
brew install tesseract tesseract-lang
```

Tesseract kurulu değilse panel bunu belirtir ve yalnızca QR okunur.

## Toplu tarama

Panelde **Toplu tarama** bölümünden ya da komut satırından:

```bash
.venv/bin/python -m kalkan.bulk posta_kutusu.mbox --csv sonuc.csv
```

Gmail posta kutusu Google Paketler'den (takeout.google.com) `.mbox` olarak indirilebilir. Toplu taramada içerik Claude'a gönderilmez. Yalnızca uyarı alan öğeler geçmişe yazılır.

## Doğruluğu kendiniz ölçün

```bash
.venv/bin/python -m kalkan.degerlendirme.calistir --indir --egit --etiket sonra
```

Bu komut sırayla şunları yapar:
1. Açık veri setlerini (Nazario, SpamAssassin, UCI SMS, UCI Turkish Spam, PhiUSIIL) `veri_setleri/` klasörüne indirir. Bu klasör depoya eklenmez.
2. Modelleri eğitim bölmesiyle eğitir.
3. Görülmemiş test bölmesinde ölçer ve sonucu yazdırır.

`--paket` eklenirse eğitilen modeller depodaki `kalkan/ml/modeller/` klasörüne kopyalanır.

Kurumunuzdan gelen gerçek ve anonimleştirilmiş örneklerle ölçmek en güvenilir yoldur. Özellikle Türkçe phishing için bu gereklidir. Kendi CSV'nizle (`metin,etiket`) eğitmek için:

```bash
.venv/bin/python -m kalkan.ml.egit --csv kendi_verim.csv --tohum
```

## Ayarlar (ortam değişkenleri ya da `.env`)

| Değişken | Açıklama |
|---|---|
| `KALKAN_TOKEN` | Panel/API erişim anahtarı. Sunucu `127.0.0.1` dışında yayınlanacaksa **mutlaka** tanımlayın. Eklenti ayarlarına da girin. |
| `KALKAN_SUPHELI_ESIK`, `KALKAN_TEHLIKELI_ESIK` | Seviye eşikleri (varsayılan 30 / 60) |
| `KALKAN_METIN_ML_ESIK`, `KALKAN_URL_ML_ESIK` | ML modellerinin bulgu eklediği olasılık eşikleri (varsayılan 0,8 / 0,9) |
| `KALKAN_LLM=1` | Claude katmanını açar. Kimlik bilgisi `ANTHROPIC_API_KEY` ya da `ant auth login` ile okunur. |
| `KALKAN_LLM_MODEL` | Varsayılan `claude-opus-5-5` |
| `VIRUSTOTAL_API_KEY` | Dosya hash sorgusu |
| `KALKAN_WEBHOOK_URL` | Slack/Teams gelen webhook adresi |
| `KALKAN_INDIRME_DIZINI` | Eklentinin indirdiği dosyaların okunabileceği tek klasör (varsayılan `~/Downloads`) |
| `KALKAN_OTOMATIK_TARAMA_SAAT` | Otomatik hızlı bilgisayar taraması aralığı, saat (varsayılan 24, `0` kapatır) |
| `KALKAN_KARANTINA_DIR` | Karantina klasörü (varsayılan `~/.kalkan/karantina`) |
| `KALKAN_WATCH_DIR` | İzlenecek klasör, ör. `~/Downloads` |
| `KALKAN_IMAP_HOST`, `KALKAN_IMAP_USER`, `KALKAN_IMAP_PASSWORD`, `KALKAN_IMAP_FOLDER` | Posta kutusu izleme. Uygulamaya özel şifre kullanın. |
| `KALKAN_MAX_DOSYA_MB`, `KALKAN_MAX_TOPLU_MB` | Yükleme sınırları (varsayılan 25 / 200) |

Örnek dosya: `.env.example`. Gizli değerleri koda ya da depoya yazmayın.

## KVKK ve gizlilik

- Veritabanında içeriğin tamamı saklanmaz. Kısa etiket (konu ya da ilk 80 karakter, uzun sayılar maskeli) ve bulgular saklanır. Tarayıcı ve toplu taramalarda temiz sonuçlar yalnızca günlük sayaca yansır.
- LLM katmanı **varsayılan olarak kapalıdır**. Açıldığında paneldeki e-posta/SMS metni ve URL Anthropic API'ye gönderilir (yurt dışına aktarım). Tarayıcı, toplu tarama ve klasör izleme içerikleri ile dosyaların kendisi hiçbir zaman gönderilmez. Açmadan önce kurumunuzun KVKK değerlendirmesini ve çalışan aydınlatmasını yapın.
- VirusTotal'e yalnızca SHA-256 hash gönderilir.
- Değerlendirme veri setlerindeki hata örnekleri depoya eklenmez, çünkü bu veri setlerinde gerçek kişilerin adları geçebilir.

## Testler

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## Sınırlar

Kalkan bir antivirüs ya da e-posta ağ geçidinin yerini tutmaz, onlara ek bir katmandır. Dosyaları çalıştırmaz (sandbox yok), bağlantıları açmaz. Tespit statik analize dayanır. Yeni ve hedefli saldırıları kaçırabilir. URL tespiti orta düzeydedir: phishing adreslerinin yaklaşık yarısı yalnızca adresten tanınabiliyor. Eklentinin sayfa içi kontrolü bu açığı kısmen kapatır. Sonuçları çalışan farkındalık eğitimiyle birlikte kullanın.

## Yol haritası önerileri

- Türkçe phishing örnekleriyle (kurum içi, anonimleştirilmiş) ölçüm ve eğitim
- USOM zararlı bağlantı listesi entegrasyonu
- Panelde "yanlış alarm / kaçırılmış tehdit" geri bildirimi ve bununla yeniden eğitim
- YARA kuralları
- Outlook / Gmail eklentisi
