"""URL analizi: alan adı taklidi, şüpheli yapı ve kısaltıcı tespiti.

Ağ isteği yapmaz; bağlantıyı açmadan yalnızca metin olarak inceler.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import List, Tuple
from urllib.parse import urlsplit

from ..models import Bulgu, Sonuc, sonuclandir

# Taklit edilmesi sık görülen markaların resmî alan adları (kayıtlı kök alan).
RESMI_ALANLAR = {
    "turkiye.gov.tr": "e-Devlet",
    "ptt.gov.tr": "PTT",
    "gib.gov.tr": "GİB",
    "yurticikargo.com": "Yurtiçi Kargo",
    "araskargo.com.tr": "Aras Kargo",
    "mngkargo.com.tr": "MNG Kargo",
    "suratkargo.com.tr": "Sürat Kargo",
    "garantibbva.com.tr": "Garanti BBVA",
    "akbank.com": "Akbank",
    "ziraatbank.com.tr": "Ziraat Bankası",
    "isbank.com.tr": "İş Bankası",
    "yapikredi.com.tr": "Yapı Kredi",
    "vakifbank.com.tr": "VakıfBank",
    "halkbank.com.tr": "Halkbank",
    "qnb.com.tr": "QNB",
    "denizbank.com": "DenizBank",
    "enpara.com": "Enpara",
    "papara.com": "Papara",
    "turkcell.com.tr": "Turkcell",
    "vodafone.com.tr": "Vodafone",
    "turktelekom.com.tr": "Türk Telekom",
    "trendyol.com": "Trendyol",
    "hepsiburada.com": "Hepsiburada",
    "sahibinden.com": "sahibinden",
    "paypal.com": "PayPal",
    "apple.com": "Apple",
    "icloud.com": "iCloud",
    "microsoft.com": "Microsoft",
    "office.com": "Microsoft 365",
    "live.com": "Outlook",
    "google.com": "Google",
    "netflix.com": "Netflix",
    "instagram.com": "Instagram",
    "facebook.com": "Facebook",
    "whatsapp.com": "WhatsApp",
    "amazon.com": "Amazon",
    "amazon.com.tr": "Amazon",
    "dhl.com": "DHL",
    "binance.com": "Binance",
}

# Alan adında geçtiğinde taklit şüphesi doğuran anahtar sözcükler -> resmî kök alanlar
MARKA_ANAHTARLARI = {
    "edevlet": ["turkiye.gov.tr"], "e-devlet": ["turkiye.gov.tr"], "turkiye-gov": ["turkiye.gov.tr"],
    "ptt": ["ptt.gov.tr"], "yurtici": ["yurticikargo.com"], "araskargo": ["araskargo.com.tr"],
    "mngkargo": ["mngkargo.com.tr"], "garanti": ["garantibbva.com.tr"], "akbank": ["akbank.com"],
    "ziraat": ["ziraatbank.com.tr"], "isbank": ["isbank.com.tr"], "yapikredi": ["yapikredi.com.tr"],
    "vakifbank": ["vakifbank.com.tr"], "halkbank": ["halkbank.com.tr"], "denizbank": ["denizbank.com"],
    "enpara": ["enpara.com"], "papara": ["papara.com"], "turkcell": ["turkcell.com.tr"],
    "vodafone": ["vodafone.com.tr"], "trendyol": ["trendyol.com"], "hepsiburada": ["hepsiburada.com"],
    "sahibinden": ["sahibinden.com"], "paypal": ["paypal.com"], "apple": ["apple.com"],
    "icloud": ["icloud.com"], "microsoft": ["microsoft.com"], "office365": ["office.com"],
    "outlook": ["live.com", "microsoft.com"], "netflix": ["netflix.com"], "instagram": ["instagram.com"],
    "facebook": ["facebook.com"], "whatsapp": ["whatsapp.com"], "amazon": ["amazon.com", "amazon.com.tr"],
    "binance": ["binance.com"], "dhl": ["dhl.com"],
}

KISALTICILAR = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly",
    "shorturl.at", "rb.gy", "t.ly", "s.id", "tiny.cc", "bl.ink", "short.io", "v.gd",
}

SUPHELI_TLD = {
    "zip", "mov", "xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "buzz", "rest", "icu",
    "cyou", "sbs", "cfd", "lol", "monster", "quest", "support", "live", "online", "site", "shop",
}

YOL_ANAHTARLARI = (
    "login", "signin", "verify", "verification", "secure", "account", "update", "confirm", "banking",
    "password", "wallet", "giris", "dogrula", "dogrulama", "guncelle", "odeme", "iade", "aidat",
    "kargo-takip", "teslimat",
)

# İki parçalı ülke kodlu ekler (kök alanı doğru bulmak için)
IKI_PARCALI_EKLER = {
    "com.tr", "gov.tr", "org.tr", "net.tr", "edu.tr", "k12.tr", "bel.tr", "co.uk", "org.uk",
    "com.au", "co.jp", "com.br",
}

URL_REGEX = re.compile(
    r"""(?ix)
    \b(
      (?:https?://|www\.)[^\s<>"'()]+
      |
      (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})(?:/[^\s<>"'()]*)?
    )"""
)
# Sık görülen dosya adı uzantıları URL sanılmasın
_DOSYA_UZANTILARI = {"pdf", "doc", "docx", "xls", "xlsx", "exe", "zip", "rar", "jpg", "png", "txt", "html"}

# Görsel olarak harfe benzeyen rakamlar / karakterler
_BENZER = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})


def urlleri_bul(metin: str) -> List[str]:
    bulunan: List[str] = []
    for m in URL_REGEX.finditer(metin or ""):
        u = m.group(1).rstrip(".,;:!?)]}'\"")
        if "://" not in u and not u.lower().startswith("www."):
            son = u.split("/")[0].rsplit(".", 1)[-1].lower()
            if son in _DOSYA_UZANTILARI or "@" in metin[max(0, m.start() - 1):m.start()]:
                continue
        if u not in bulunan:
            bulunan.append(u)
    return bulunan


def _kok_alan(host: str) -> str:
    parcalar = host.split(".")
    if len(parcalar) >= 3 and ".".join(parcalar[-2:]) in IKI_PARCALI_EKLER:
        return ".".join(parcalar[-3:])
    return ".".join(parcalar[-2:])


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    onceki = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        simdiki = [i]
        for j, cb in enumerate(b, 1):
            simdiki.append(min(onceki[j] + 1, simdiki[j - 1] + 1, onceki[j - 1] + (ca != cb)))
        onceki = simdiki
    return onceki[-1]


def _resmi_mi(kok: str) -> bool:
    return kok in RESMI_ALANLAR


def url_analiz(ham_url: str, kaynak: str = "panel") -> Sonuc:
    url = ham_url.strip()
    if not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", url):
        url = "http://" + url
    bulgular: List[Bulgu] = []
    try:
        parca = urlsplit(url)
        host = (parca.hostname or "").lower().rstrip(".")
    except ValueError:
        return sonuclandir(Sonuc("url", ham_url[:200], bulgular=[
            Bulgu("gecersiz_url", "URL ayrıştırılamadı; bozuk ya da kasıtlı olarak karıştırılmış olabilir.", 40, "phishing")
        ], kaynak=kaynak))

    sonuc = Sonuc("url", ham_url[:200], kaynak=kaynak)
    sonuc.ek["host"] = host

    if not host:
        bulgular.append(Bulgu("host_yok", "Bağlantıda alan adı bulunamadı.", 30, "phishing"))
        sonuc.bulgular = bulgular
        return sonuclandir(sonuc)

    # 1) IP adresiyle doğrudan bağlantı
    try:
        ipaddress.ip_address(host.strip("[]"))
        bulgular.append(Bulgu("ip_host", "Alan adı yerine doğrudan IP adresi kullanılmış.", 45, "phishing"))
    except ValueError:
        pass

    # 2) Punycode / Unicode benzer harf saldırısı
    if "xn--" in host:
        bulgular.append(Bulgu("punycode", "Alan adı punycode (xn--) içeriyor; Latin harflerine benzeyen yabancı karakterler olabilir.", 45, "phishing"))
    elif any(ord(c) > 127 for c in host):
        karisik = {unicodedata.name(c, "").split(" ")[0] for c in host if c.isalpha()}
        agirlik = 55 if len(karisik) > 1 else 30
        bulgular.append(Bulgu("unicode_host", "Alan adında ASCII dışı karakter var (homograf saldırısı riski).", agirlik, "phishing"))

    # 3) Kullanıcı adı hilesi: https://guvenli-banka.com@kotu.site
    if "@" in (parca.netloc or ""):
        bulgular.append(Bulgu("at_isareti", "Adreste '@' var: tarayıcı '@' öncesini yok sayar, gerçek hedef sonrasıdır.", 50, "phishing"))

    # 4) Kısaltıcı
    kok = _kok_alan(host)
    sonuc.ek["kok_alan"] = kok
    if host in KISALTICILAR or kok in KISALTICILAR:
        bulgular.append(Bulgu("kisaltici", "Kısaltılmış bağlantı: asıl hedef gizleniyor.", 25, "phishing"))

    # 5) Şüpheli üst düzey alan
    tld = host.rsplit(".", 1)[-1]
    if tld in SUPHELI_TLD:
        bulgular.append(Bulgu("supheli_tld", f".{tld} uzantısı kötüye kullanımda sık görülür.", 20, "phishing"))

    # 6) Marka taklidi: markanın adı geçiyor ama resmî alan değil
    resmi = _resmi_mi(kok)
    if not resmi:
        duz = host.replace(".", "-")
        benzer = duz.translate(_BENZER)
        parcalar = set(re.split(r"[.-]", host)) | set(re.split(r"[.-]", host.translate(_BENZER)))

        def _gecer(anahtar: str) -> bool:
            # "pineapple" içindeki "apple" gibi rastlantısal eşleşmeleri ele: tam parça ya da parça başı ara
            if "-" in anahtar:
                return f"-{anahtar}-" in f"-{duz}-" or f"-{anahtar}-" in f"-{benzer}-"
            for p in parcalar:
                if p == anahtar or (len(anahtar) >= 5 and p.startswith(anahtar)):
                    return True
            return False

        for anahtar, resmiler in MARKA_ANAHTARLARI.items():
            if _gecer(anahtar):
                marka = RESMI_ALANLAR.get(resmiler[0], anahtar)
                bulgular.append(Bulgu(
                    "marka_taklidi",
                    f"Adreste '{marka}' adı geçiyor ama resmî alan adı ({', '.join(resmiler)}) değil.",
                    60, "phishing",
                ))
                break
        else:
            # 7) Yazım hatası taklidi (typosquatting): garanntibbva.com.tr, paypa1.com
            govde = kok.split(".")[0]
            govde_benzer = govde.translate(_BENZER)
            for resmi_alan, marka in RESMI_ALANLAR.items():
                r_govde = resmi_alan.split(".")[0]
                if len(r_govde) < 5:
                    continue
                mesafe = min(_levenshtein(govde, r_govde), _levenshtein(govde_benzer, r_govde))
                if 0 < mesafe <= (1 if len(r_govde) < 8 else 2) or (govde != r_govde and govde_benzer == r_govde):
                    bulgular.append(Bulgu(
                        "yazim_taklidi",
                        f"'{kok}' alan adı '{resmi_alan}' ({marka}) adresine çok benziyor.",
                        65, "phishing",
                    ))
                    break

    # 8) Yapısal sinyaller
    alt_alan_sayisi = max(host.count(".") - kok.count("."), 0)
    if alt_alan_sayisi >= 3:
        bulgular.append(Bulgu("cok_alt_alan", f"{alt_alan_sayisi} katmanlı alt alan adı; gerçek alanı gizlemek için kullanılır.", 20, "phishing"))
    if host.replace("xn--", "").count("-") >= 3:
        bulgular.append(Bulgu("cok_tire", "Alan adında çok sayıda tire var.", 15, "phishing"))
    if len(url) > 120:
        bulgular.append(Bulgu("uzun_url", "Bağlantı alışılmadık derecede uzun.", 10, "phishing"))
    if parca.scheme == "http" and not resmi and ham_url.lower().startswith("http://"):
        bulgular.append(Bulgu("sifresiz", "Bağlantı şifresiz (http) bağlantı kullanıyor.", 10, "phishing"))
    if parca.port and parca.port not in (80, 443):
        bulgular.append(Bulgu("standart_disi_port", f"Standart dışı port: {parca.port}.", 15, "phishing"))

    yol = f"{parca.path}?{parca.query}".lower()
    eslesen = [k for k in YOL_ANAHTARLARI if k in yol or (not resmi and k in host)]
    if eslesen and not resmi:
        bulgular.append(Bulgu("hassas_yol", f"Bağlantıda giriş/doğrulama ifadeleri var: {', '.join(eslesen[:4])}.", 20, "phishing"))
    if re.search(r"\.(exe|scr|apk|msi|bat|cmd|js|vbs|hta|iso|zip|rar)(\?|$)", parca.path.lower()):
        bulgular.append(Bulgu("dosya_indirme", "Bağlantı doğrudan çalıştırılabilir ya da arşiv dosyası indiriyor.", 40, "zararli"))
    if re.search(r"(?i)(redirect|url|next|goto|dest)=https?%3a|=https?://", parca.query or ""):
        bulgular.append(Bulgu("yonlendirme", "Bağlantı başka bir adrese yönlendirme parametresi taşıyor.", 15, "phishing"))

    sonuc.bulgular = bulgular
    return sonuclandir(sonuc)


def en_riskli(urller: List[str]) -> Tuple[List[Sonuc], int]:
    sonuclar = [url_analiz(u) for u in urller[:30]]
    return sonuclar, max((s.puan for s in sonuclar), default=0)
