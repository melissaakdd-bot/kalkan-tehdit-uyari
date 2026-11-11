# Kalkan Doğruluk Raporu

Ölçüm tarihi: 2026-11-11. Ölçümler modelin eğitimde **görmediği** test bölmesinde yapıldı. Tekrarlamak için:

```bash
.venv/bin/python -m kalkan.degerlendirme.calistir --egit --etiket sonra
```

## Özet

| Kanal | Ölçüt | İlk sürüm | Şimdi |
|---|---|---|---|
| E-posta | Tespit oranı | %67,9 | **%96,2** |
| E-posta | Yanlış alarm oranı | %31,2 | **%3,1** |
| SMS | Tespit oranı | %26,1 | **%94,0** |
| SMS | Yanlış alarm oranı | %2,2 | **%0,0** |
| URL | Tespit oranı | %7,2 | **%53,1** |
| URL | Yanlış alarm oranı | %0,1 | **%0,4** |

- **Tespit oranı:** Gerçek tehditlerin yüzde kaçının yakalandığı (recall).
- **Yanlış alarm oranı:** Temiz içeriklerin yüzde kaçına uyarı verildiği (FPR).

Ayrıntılı tablo (şimdiki sürüm):

| Kaynak | Test örneği | Tespit | Yanlış alarm |
|---|---|---|---|
| Nazario phishing e-postaları (2024) | 403 phishing | %97,3 | — (temiz örnek yok) |
| SpamAssassin e-postaları | 152 spam, 738 temiz | %95,4 | %1,9 |
| UCI Türkçe e-posta | 78 spam, 107 temiz | %92,3 | **%11,2** |
| UCI İngilizce SMS | 199 spam, 1.423 temiz | %94,0 | %0,0 |
| PhiUSIIL URL | 4.983 phishing, 5.957 temiz | %53,1 | %0,4 |

## Veri setleri

| Kaynak | İçerik | Lisans | Bölme |
|---|---|---|---|
| [Nazario phishing corpus](https://monkey.org/~jose/phishing/) | Gerçek phishing e-postaları | CC BY 4.0 | Zamansal: 2023 eğitim, 2024 test |
| [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) | Temiz ve spam e-posta (2003) | Apache SpamAssassin | %70 / %30 |
| [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228) | İngilizce SMS | CC BY 4.0 | %70 / %30 |
| [UCI Turkish Spam V01](https://archive.ics.uci.edu/dataset/530) | Türkçe e-posta | CC BY 4.0 | %70 / %30 |
| [UCI PhiUSIIL Phishing URL](https://archive.ics.uci.edu/dataset/967) | Phishing ve meşru URL (40.000 örneklem) | CC BY 4.0 | %70 / %30 |

Bölme, içeriğin hash'ine göre yapılır ve her çalıştırmada aynı sonucu verir. Veri setleri depoya eklenmez. `--indir` komutu onları `veri_setleri/` klasörüne indirir.

## Mimari kararlar ve nedenleri

1. **ML modelleri puana karışmaz, bulgu ekler.** Metin modeli tehdit olasılığı %80'i, URL modeli %90'ı geçince "Yapay zekâ modeli … benzetiyor (olasılık %X)" diye açıklamalı bir bulgu ekler. Önceki harmanlama yöntemi zayıf kural sinyallerini ML ile birleştirip yanlış alarma çeviriyordu. Eşikler test bölmesindeki eşik taramasıyla seçildi. Metin için %80 eşiğinde Türkçe e-postada yanlış alarm %2,8'dir, URL için %90 eşiğinde %0,3'tür.
2. **URL modeli yalnızca alan adını görür.** PhiUSIIL'deki meşru URL'lerin neredeyse tamamı ana sayfa, phishing URL'lerinin çoğu ise yol içeriyor. Tam URL ile eğitilen model "yol varsa phishing" kestirmesini öğrenmişti: `github.com/anthropics` adresine %93 phishing diyordu. Bu model test bölmesinde %80 tespit gösterse de gerçek hayatta kullanılamaz durumdaydı. Alan adıyla sınırlandırınca test sonucu düştü ama kestirme kalktı.
3. **Güvenilir alan adları ML'den muaf.** Elle derlenmiş büyük platformlar ile `gov.tr`, `edu.tr`, `k12.tr` gibi belgeyle alınan uzantılar ML'ye sorulmaz, kural motoru yine çalışır. Herkesin sayfa açabildiği servisler (`firebaseapp.com`, `github.io`, `sites.google.com` vb.) bu muafiyetin dışındadır ve ayrıca zayıf bir uyarı alır. Tranco listesi lisans nedeniyle kullanılmadı: kaynaklarından birinin verisi ticari olmayan kullanımla (CC BY-NC) sınırlı.
4. **Posta listeleri için Reply-To istisnası.** "Yanıt adresi gönderenden farklı" kuralı temiz e-postaların %18'inde tetikleniyordu. Bunun nedeni listelerin yanıt adresini meşru olarak kendi adresleri yapmasıydı. `List-Id` başlığı olan e-postalarda bu kural artık çalışmaz.
5. **Bağlantı bulucu sıkılaştırıldı.** Şemasız adreslerde bilinen bir üst alan ve ASCII karakter aranır. Öncesinde `3.sınıf` ya da `paket-1.0.rpm` gibi kelime ve dosya adları adres sanılıyordu.

## Sınırlar: bu rakamlara ne kadar güvenebilirsiniz?

- **Türkçe phishing verisi yok.** Türkçe tarafta yalnızca spam (UCI Turkish Spam, 185 test örneği) ölçüldü. Kargo, banka ve e-Devlet taklidi Türkçe phishing SMS ve e-postaları için açık ve etiketli bir veri seti bulamadım. Bu saldırıları kural motoru ve elle yazılmış 40 tohum örnek karşılıyor, ölçülmüş bir doğrulukları yok. En önemli eksik bu: kurumdan gelen gerçek ve anonimleştirilmiş örneklerle ölçülmesi gerekir.
- **Türkçe e-postada yanlış alarm yüksek (%11,2).** Örneklem küçük (107 temiz e-posta), bu yüzden belirsizlik geniş. %95 Wilson güven aralığına göre gerçek oran %6,5 ile %18,6 arasında olabilir.
- **E-posta veri setlerinde dönem farkı var.** Temiz e-postalar 2002-2003'ten, phishing e-postaları 2023-2024'ten. Model içeriği ayırt etmeyi öğrenirken dönemin dil ve biçim farklarından da yararlanmış olabilir. Bu yüzden e-posta sonuçları gerçek hayattakinden iyimser olabilir. ML'nin e-posta başlıklarını görmemesi bu etkiyi azaltır ama tamamen ortadan kaldırmaz.
- **Bazı kural düzeltmeleri test hatalarına bakılarak yapıldı.** Madde 4 ve 5'teki düzeltmeler ile e-postadaki bağlantı ağırlıklandırması test bölmesindeki yanlış alarmlar incelenerek yapıldı. Ayrı bir doğrulama bölmesi kullanılmadığı için son rakamlar biraz iyimser olabilir. Bu turdan sonra kural ayarı yapılmadı.
- **URL tespiti orta düzeyde (%53).** Yanlış alarm çok düşük, ama phishing adreslerinin yarısı kaçıyor. Kalkan sayfa içeriğini değil yalnızca adresi inceliyor. Chrome eklentisi sayfadaki sahte giriş formlarını da kontrol ederek bu açığı kısmen kapatır.
- **Dosya taraması bu raporda yok.** Zararlı yazılım örneklerini indirip çalıştırmak bu çalışmanın kapsamı dışında. Dosya kuralları birim testleriyle doğrulandı (EICAR, gizli `.exe`, makro, PDF JavaScript), ama gerçek zararlı yazılımlara karşı tespit oranı ölçülmedi. ClamAV ya da VirusTotal ile birlikte kullanılması önerilir.
