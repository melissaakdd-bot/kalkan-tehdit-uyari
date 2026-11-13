"""E-posta ve SMS metni analizi: kural sinyalleri + ML sınıflandırıcı + bağlantı taraması."""
from __future__ import annotations

import email
import re
from email import policy
from email.utils import parseaddr
from typing import Dict, List, Optional, Tuple

from .. import config
from ..ml import model as ml_model
from ..models import Bulgu, Sonuc, sonuclandir
from .url import RESMI_ALANLAR, _kok_alan, url_analiz, urlleri_bul


def _norm(metin: str) -> str:
    """Türkçe karakterleri sadeleştirip küçük harfe çevirir: kural eşleşmeleri iki yazımı da yakalar."""
    tablo = str.maketrans("ÇĞİIÖŞÜçğıöşü", "cgiiosucgiosu")
    return metin.translate(tablo).lower()


# (kod, açıklama, ağırlık, kategori, desenler) — desenler _norm uygulanmış metinde aranır
KURALLAR: List[Tuple[str, str, int, str, List[str]]] = [
    ("aciliyet", "Aciliyet ve baskı dili kullanılıyor.", 18, "phishing", [
        r"\bacil\b", r"\bhemen\b", r"24 saat", r"48 saat", r"son gun", r"son \d+ saat", r"derhal",
        r"askiya al", r"kapatilacak", r"bloke", r"iptal edilecek", r"urgent", r"immediately",
        r"suspended", r"within 24 hours", r"action required", r"son uyari",
    ]),
    ("kimlik_bilgisi", "Şifre, kart, doğrulama kodu gibi gizli bilgi isteniyor.", 35, "phishing", [
        r"sifre", r"parola", r"dogrulama kodu", r"sms kodu", r"onay kodu", r"tek kullanimlik",
        r"kart numara", r"\bcvv\b", r"\bcvc\b", r"son kullanma tarihi", r"tc kimlik", r"t\.c\. kimlik",
        r"kimlik numara", r"password", r"verify your (account|identity)", r"login credentials",
        r"internet bankaciligi bilgi", r"hesap bilgilerinizi",
    ]),
    ("hesap_tehdidi", "Hesabın kapatılacağı, cezalandırılacağı ya da haciz uygulanacağı söyleniyor.", 25, "phishing", [
        r"hesabiniz.{0,30}(askiya|kapat|bloke|kilitlen|dondur)", r"icra", r"haciz", r"yasal islem",
        r"ceza(si)? (kesil|uygulan)", r"account.{0,20}(locked|suspended|closed)", r"unusual (sign-in|activity)",
        r"supheli (giris|islem)",
    ]),
    ("odeme_talebi", "Küçük bir ücret, gümrük vergisi ya da borç ödemesi isteniyor.", 22, "phishing", [
        r"gumruk (ucret|vergi)", r"teslimat ucreti", r"adres(iniz)? (eksik|hatali)", r"kargonuz.{0,40}(bekle|teslim edilemedi|depoda)",
        r"borcunuz", r"odenmemis", r"fatura(niz)? (odenmedi|gecikti)", r"aidat", r"iade (talebi|tutari)",
        r"vergi iadesi", r"refund", r"payment (failed|declined)", r"outstanding (balance|invoice)",
    ]),
    ("odul_vaadi", "Ödül, hediye, çekiliş ya da bedava teklif var.", 22, "spam", [
        r"kazandiniz", r"kazanan", r"cekilis", r"hediye (ceki|kart)", r"bedava", r"ucretsiz .{0,15}(iphone|telefon|tatil)",
        r"odul", r"you (have )?won", r"winner", r"lottery", r"free (gift|iphone)", r"congratulations",
        r"tebrikler",
    ]),
    ("yatirim_dolandiriciligi", "Garantili kazanç, kripto ya da yüksek getiri vaadi var.", 25, "spam", [
        r"garantili (kazanc|getiri)", r"gunluk \d+.{0,5}(tl|dolar|\$)", r"kripto", r"bitcoin", r"forex",
        r"pasif gelir", r"evden calisarak", r"yatirim (firsati|grubu)", r"guaranteed (profit|return)",
        r"double your",
    ]),
    ("kredi_bahis", "Kredi, bahis ya da kumar reklamı.", 20, "spam", [
        r"kredi (notu|onay|basvuru)", r"aninda kredi", r"bahis", r"\bbonus\b", r"casino", r"freespin",
        r"deneme bonusu", r"slot",
    ]),
    ("pazarlama", "Toplu pazarlama mesajı özellikleri var.", 10, "spam", [
        r"abonelikten cik", r"unsubscribe", r"\bret\b.{0,10}\d{4}", r"\bb\d{3}\b", r"mersis",
        r"kampanya", r"indirim", r"firsat",
    ]),
    ("zararli_ek", "Mesaj çalıştırılabilir ya da makrolu bir eki açmanızı istiyor.", 35, "zararli", [
        r"\.(exe|scr|bat|cmd|vbs|js|hta|msi|iso|apk|docm|xlsm)\b", r"makrolari etkinlestir",
        r"enable (macros|content|editing)", r"icerigi etkinlestir", r"ekteki (dosyayi|faturayi) ac",
        r"uygulamayi (indir|yukle)", r"\.apk",
    ]),
    ("uzaktan_erisim", "Uzaktan erişim programı kurdurma girişimi var.", 40, "zararli", [
        r"anydesk", r"teamviewer", r"rustdesk", r"quick ?support", r"uzaktan baglan",
    ]),
]

MARKA_ADLARI = {
    "e-devlet": "turkiye.gov.tr", "edevlet": "turkiye.gov.tr", "ptt": "ptt.gov.tr", "yurtici kargo": "yurticikargo.com",
    "aras kargo": "araskargo.com.tr", "mng kargo": "mngkargo.com.tr", "garanti": "garantibbva.com.tr",
    "akbank": "akbank.com", "ziraat": "ziraatbank.com.tr", "is bankasi": "isbank.com.tr", "yapi kredi": "yapikredi.com.tr",
    "vakifbank": "vakifbank.com.tr", "halkbank": "halkbank.com.tr", "turkcell": "turkcell.com.tr",
    "vodafone": "vodafone.com.tr", "turk telekom": "turktelekom.com.tr", "trendyol": "trendyol.com",
    "hepsiburada": "hepsiburada.com", "paypal": "paypal.com", "apple": "apple.com", "microsoft": "microsoft.com",
    "netflix": "netflix.com", "instagram": "instagram.com", "amazon": "amazon.com", "gib": "gib.gov.tr",
    "sgk": "sgk.gov.tr", "emniyet": "egm.gov.tr", "dhl": "dhl.com",
}


def _eposta_mi(metin: str) -> bool:
    bas = metin.lstrip()[:2000]
    return bool(re.search(r"(?im)^(from|subject|received|return-path|message-id):", bas))


def _eposta_ayristir(ham: str) -> Dict[str, object]:
    msg = email.message_from_string(ham, policy=policy.default)
    govde_parcalari: List[str] = []
    ekler: List[Dict[str, object]] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ad = part.get_filename()
        if ad or part.get_content_disposition() == "attachment":
            try:
                veri = part.get_payload(decode=True) or b""
            except Exception:
                veri = b""
            ekler.append({"ad": ad or "adsiz", "veri": veri})
            continue
        if part.get_content_type() in ("text/plain", "text/html"):
            try:
                icerik = part.get_content()
            except Exception:
                icerik = str(part.get_payload())
            if part.get_content_type() == "text/html":
                # href hedeflerini koru, etiketleri at
                hrefler = re.findall(r'(?i)href=["\']([^"\']+)', icerik)
                icerik = re.sub(r"<[^>]+>", " ", icerik) + "\n" + "\n".join(hrefler)
            govde_parcalari.append(icerik)
    return {
        "from": str(msg.get("From", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "return_path": str(msg.get("Return-Path", "")),
        "subject": str(msg.get("Subject", "")),
        "auth": " ".join(str(v) for v in (msg.get_all("Authentication-Results") or [])),
        # Posta listeleri Reply-To'yu meşru olarak listenin adresine çevirir
        "liste": bool(msg.get("List-Id") or msg.get("List-Post") or msg.get("List-Unsubscribe")),
        "govde": "\n".join(govde_parcalari) if govde_parcalari else str(msg.get_payload() or ""),
        "ekler": ekler,
    }


def _baslik_bulgulari(p: Dict[str, object]) -> List[Bulgu]:
    bulgular: List[Bulgu] = []
    gor_ad, gonderen = parseaddr(str(p["from"]))
    gonderen_alan = gonderen.split("@")[-1].lower() if "@" in gonderen else ""
    _, yanit = parseaddr(str(p["reply_to"]))
    yanit_alan = yanit.split("@")[-1].lower() if "@" in yanit else ""

    if gonderen_alan and yanit_alan and _kok_alan(gonderen_alan) != _kok_alan(yanit_alan) and not p.get("liste"):
        # Tek başına zayıf sinyal: bülten servisleri de farklı yanıt adresi kullanır
        bulgular.append(Bulgu("reply_to_farkli", f"Yanıt adresi ({yanit_alan}) gönderen alanından ({gonderen_alan}) farklı.", 15, "phishing"))

    auth = _norm(str(p["auth"]))
    for mekanizma in ("spf", "dkim", "dmarc"):
        if re.search(rf"{mekanizma}=(fail|softfail|permerror)", auth):
            bulgular.append(Bulgu(f"{mekanizma}_fail", f"{mekanizma.upper()} doğrulaması başarısız: gönderen sahte olabilir.", 35, "phishing"))

    gor_norm = _norm(gor_ad)
    if gonderen_alan:
        kok = _kok_alan(gonderen_alan)
        for marka, resmi in MARKA_ADLARI.items():
            if re.search(rf"\b{re.escape(marka)}\b", gor_norm) and kok != resmi and not kok.endswith("." + resmi):
                bulgular.append(Bulgu(
                    "gorunen_ad_taklidi",
                    f"Gönderen adı '{gor_ad}' ama adres {gonderen_alan}; resmî alan {resmi}.",
                    45, "phishing",
                ))
                break
        if re.search(r"(gmail|hotmail|outlook|yahoo|yandex)\.", gonderen_alan) and any(
            re.search(rf"\b{re.escape(m)}\b", gor_norm) for m in MARKA_ADLARI
        ):
            bulgular.append(Bulgu("ucretsiz_posta_kurum", "Kurum adıyla ücretsiz e-posta servisinden gönderilmiş.", 30, "phishing"))
    return bulgular


def metin_analiz(icerik: str, tur: str = "eposta", kaynak: str = "panel") -> Sonuc:
    """tur: 'eposta' ya da 'sms'. Ham e-posta (başlıklarla) verilirse başlıklar da incelenir."""
    from .file import dosya_analiz  # döngüsel içe aktarmayı önle

    icerik = icerik or ""
    bulgular: List[Bulgu] = []
    ek_sonuclari: List[Sonuc] = []
    konu = ""
    govde = icerik

    if tur == "eposta" and _eposta_mi(icerik):
        p = _eposta_ayristir(icerik)
        konu = str(p["subject"])
        govde = f"{konu}\n{p['govde']}"
        bulgular += _baslik_bulgulari(p)
        for ek in p["ekler"]:  # type: ignore[union-attr]
            es = dosya_analiz(ek["veri"], str(ek["ad"]), kaynak=kaynak)
            ek_sonuclari.append(es)
            if es.seviye != "guvenli":
                bulgular.append(Bulgu(
                    "riskli_ek", f"Ek '{ek['ad']}' riskli bulundu (puan {es.puan}).",
                    es.puan, "zararli", kritik=es.seviye == "tehlikeli" and any(b.kritik for b in es.bulgular),
                ))

    n = _norm(govde)
    for kod, aciklama, agirlik, kategori, desenler in KURALLAR:
        eslesen = [d for d in desenler if re.search(d, n)]
        if eslesen:
            # Birden çok desen eşleşirse sinyal biraz güçlenir
            bulgular.append(Bulgu(kod, aciklama, min(agirlik + 5 * (len(eslesen) - 1), agirlik + 15), kategori))

    # Biçimsel spam sinyalleri
    harfler = [c for c in govde if c.isalpha()]
    if len(harfler) > 30 and sum(c.isupper() for c in harfler) / len(harfler) > 0.5:
        bulgular.append(Bulgu("buyuk_harf", "Metnin büyük kısmı büyük harfle yazılmış.", 10, "spam"))
    if govde.count("!") >= 4:
        bulgular.append(Bulgu("unlem", "Çok sayıda ünlem işareti var.", 8, "spam"))
    if re.search(r"\bTR\d{2}[ ]?(\d{4}[ ]?){5}\d{2}\b", govde.replace("\n", " ")):
        bulgular.append(Bulgu("iban", "Mesajda IBAN var ve para gönderimi isteniyor olabilir.", 15, "phishing"))

    # Bağlantılar
    urller = urlleri_bul(govde)
    url_sonuclari = [url_analiz(u, kaynak=kaynak) for u in urller[:30]]
    riskli_url = [u for u in url_sonuclari if u.seviye != "guvenli"]
    talep_var = any(b.kod in ("kimlik_bilgisi", "odeme_talebi", "hesap_tehdidi") for b in bulgular)
    if riskli_url:
        en_kotu = max(riskli_url, key=lambda s: s.puan)
        # Tehlikeli bir bağlantı mesajı tek başına alarma sokar; yalnızca şüpheli olan ise yarım ağırlıkla
        # katılır ve ancak başka sinyallerle birleşirse uyarı üretir (meşru bültenlerde de bit.ly, blogspot vb. olur).
        agirlik = min(en_kotu.puan, 85) if en_kotu.seviye == "tehlikeli" else en_kotu.puan // 2
        bulgular.append(Bulgu(
            "riskli_baglanti",
            f"{len(riskli_url)} şüpheli bağlantı; en riskli: {en_kotu.hedef} (puan {en_kotu.puan}).",
            agirlik, "phishing",
        ))
    if urller and talep_var:
        bulgular.append(Bulgu("baglanti_ve_talep", "Bağlantı ile birlikte bilgi ya da ödeme isteniyor.", 20, "phishing"))

    # Marka adına yazılıp bilgi/ödeme isteyen ama bağlantıları resmî alana gitmeyen mesaj.
    # Talep şartı olmadan bu kural, markadan söz eden sıradan haber ve bültenlerde de tetikleniyordu.
    if urller and (talep_var or any(b.kod == "aciliyet" for b in bulgular)):
        for marka, resmi in MARKA_ADLARI.items():
            if re.search(rf"\b{re.escape(marka)}\b", n):
                hedefler = {u.ek.get("kok_alan") for u in url_sonuclari}
                if hedefler and not any(h == resmi or (h or "").endswith("." + resmi) for h in hedefler):
                    bulgular.append(Bulgu(
                        "marka_baglanti_uyumsuz",
                        f"Mesaj '{RESMI_ALANLAR.get(resmi, marka)}' adına yazılmış ama bağlantılar resmî alana ({resmi}) gitmiyor.",
                        35, "phishing",
                    ))
                break

    sonuc = Sonuc(tur, _etiket(tur, konu, govde), bulgular=bulgular, kaynak=kaynak)
    # ML yalnızca yüksek güvende ve açıklamalı bir bulgu olarak katılır (eşik gerçek veriyle seçildi,
    # bkz. docs/DOGRULUK.md). Puan harmanlanmaz: zayıf kural sinyalleri ML ile birleşip alarma dönüşmesin.
    tahmin: Optional[Dict[str, object]] = ml_model.tahmin_et(govde)
    if tahmin:
        sonuc.ml = tahmin
        olas = tahmin["olasiliklar"]  # type: ignore[assignment]
        tehdit = 1 - float(olas.get("temiz", 0))  # type: ignore[union-attr]
        if tehdit >= config.METIN_ML_ESIK:
            tur_ml = "phishing" if olas.get("phishing", 0) >= olas.get("spam", 0) else "spam"  # type: ignore[union-attr]
            bulgular.append(Bulgu(
                "ml_metin",
                f"Yapay zekâ modeli metni {'oltalama' if tur_ml == 'phishing' else 'spam'} örneklerine benzetiyor "
                f"(olasılık %{tehdit * 100:.0f}).",
                60 if tehdit >= 0.97 else 45, tur_ml,
            ))
    sonuc.ek["baglantilar"] = [{"url": u.hedef, "puan": u.puan, "seviye": u.seviye} for u in url_sonuclari]
    sonuc.ek["ekler"] = [{"ad": e.hedef, "puan": e.puan, "seviye": e.seviye} for e in ek_sonuclari]
    return sonuclandir(sonuc)


def ml_metni(icerik: str, tur: str = "eposta") -> str:
    """ML modelinin gördüğü metin: konu + gövde (başlıklar hariç).

    Eğitimde de bu fonksiyon kullanılır; böylece model e-posta başlıklarındaki
    veri setine özgü izleri (sunucu adları, tarih biçimleri) ezberleyemez.
    """
    if tur == "eposta" and _eposta_mi(icerik):
        p = _eposta_ayristir(icerik)
        return f"{p['subject']}\n{p['govde']}"
    return icerik


def _etiket(tur: str, konu: str, govde: str) -> str:
    """Panelde gösterilecek kısa etiket. İçeriğin tamamı saklanmaz (KVKK: veri minimizasyonu)."""
    temel = konu or re.sub(r"\s+", " ", govde).strip()
    temel = re.sub(r"\b\d{6,}\b", "[sayı]", temel)  # kimlik/kart/telefon benzeri uzun sayıları maskele
    return (temel[:80] + "…") if len(temel) > 80 else temel or f"({tur})"
