"""Açık veri setlerini indirir ve eğitim/test bölmelerine ayırır.

Dosyalar arşivden açılmadan bellekte okunur (yol aşımı vb. riskler olmasın). Hiçbir ek çalıştırılmaz.

| Kaynak | İçerik | Lisans |
|---|---|---|
| Nazario phishing corpus (monkey.org/~jose/phishing) | Gerçek phishing e-postaları, 2023 ve 2024 | CC BY 4.0 |
| SpamAssassin public corpus (2003) | Temiz ve spam e-postalar | Apache SpamAssassin projesi |
| UCI SMS Spam Collection (id 228) | İngilizce SMS, temiz/spam | CC BY 4.0 |
| UCI Turkish Spam V01 (id 530) | Türkçe e-posta, temiz/spam | CC BY 4.0 |
| UCI PhiUSIIL Phishing URL (id 967) | Phishing ve meşru URL'ler | CC BY 4.0 |
"""
from __future__ import annotations

import csv
import hashlib
import io
import mailbox
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Tuple

from .. import config

VERI_DIR = config.BASE_DIR / "veri_setleri"

KAYNAKLAR: Dict[str, str] = {
    "nazario_2023.mbox": "https://monkey.org/~jose/phishing/phishing-2023",
    "nazario_2024.mbox": "https://monkey.org/~jose/phishing/phishing-2024",
    "sa_ham.tar.bz2": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    "sa_spam.tar.bz2": "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
    "sms_en.zip": "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip",
    "tr_spam.zip": "https://archive.ics.uci.edu/static/public/530/turkish+spam+v01.zip",
    "phiusiil.zip": "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
}


@dataclass
class Ornek:
    metin: str
    etiket: str  # temiz | spam | phishing
    tur: str  # eposta | sms | url
    kaynak: str
    bolum: str  # egitim | test


def indir() -> None:
    VERI_DIR.mkdir(exist_ok=True)
    for ad, url in KAYNAKLAR.items():
        hedef = VERI_DIR / ad
        if hedef.exists() and hedef.stat().st_size > 0:
            continue
        print(f"İndiriliyor: {ad}")
        gecici = hedef.with_suffix(hedef.suffix + ".part")
        with urllib.request.urlopen(url, timeout=300) as yanit, open(gecici, "wb") as f:
            while True:
                parca = yanit.read(1 << 20)
                if not parca:
                    break
                f.write(parca)
        gecici.rename(hedef)


def _bolum(metin: str, test_orani: float = 0.3) -> str:
    """İçerik hash'ine dayalı kararlı bölme: aynı örnek her çalıştırmada aynı bölüme düşer."""
    h = int(hashlib.sha1(metin.encode("utf-8", "replace")).hexdigest()[:8], 16)
    return "test" if (h % 1000) / 1000 < test_orani else "egitim"


def _bayt_coz(b: bytes) -> str:
    for kod in ("utf-8", "latin-1"):
        try:
            return b.decode(kod)
        except UnicodeDecodeError:
            continue
    return b.decode("utf-8", "replace")


def _nazario(dosya: str, bolum: str) -> Iterator[Ornek]:
    for msg in mailbox.mbox(str(VERI_DIR / dosya)):
        ham = _bayt_coz(msg.as_bytes())
        yield Ornek(ham, "phishing", "eposta", "nazario", bolum)


def _spamassassin(dosya: str, etiket: str) -> Iterator[Ornek]:
    with tarfile.open(VERI_DIR / dosya) as tf:
        for uye in tf.getmembers():
            if not uye.isfile() or uye.name.endswith("cmds"):
                continue
            f = tf.extractfile(uye)
            if f is None:
                continue
            ham = _bayt_coz(f.read())
            yield Ornek(ham, etiket, "eposta", "spamassassin", _bolum(ham))


def _sms_en() -> Iterator[Ornek]:
    metin = zipfile.ZipFile(VERI_DIR / "sms_en.zip").read("SMSSpamCollection").decode("utf-8", "replace")
    for satir in metin.splitlines():
        if "\t" not in satir:
            continue
        etiket, mesaj = satir.split("\t", 1)
        yield Ornek(mesaj, "temiz" if etiket == "ham" else "spam", "sms", "uci_sms_en", _bolum(mesaj))


def _tr_spam() -> Iterator[Ornek]:
    metin = zipfile.ZipFile(VERI_DIR / "tr_spam.zip").read("trspam.csv").decode("utf-8-sig", "replace")
    for satir in csv.DictReader(io.StringIO(metin)):
        etiket = (satir.get("Classification") or "").strip()
        if etiket not in ("ham", "spam"):
            continue  # CSV'de tırnak hatası nedeniyle bozulmuş satırlar atlanır
        govde = satir.get("Text") or ""
        yield Ornek(govde, "temiz" if etiket == "ham" else "spam", "eposta", "uci_tr_spam", _bolum(govde))


def metin_ornekleri() -> List[Ornek]:
    """E-posta ve SMS örnekleri. Nazario için zamansal bölme: 2023 eğitim, 2024 test
    (model geçmişten öğrenip gelecekteki saldırılarda sınanır, gerçek kullanıma daha yakın)."""
    ornekler: List[Ornek] = []
    ornekler += _nazario("nazario_2023.mbox", "egitim")
    ornekler += _nazario("nazario_2024.mbox", "test")
    ornekler += _spamassassin("sa_ham.tar.bz2", "temiz")
    ornekler += _spamassassin("sa_spam.tar.bz2", "spam")
    ornekler += _sms_en()
    ornekler += _tr_spam()
    return ornekler


def url_ornekleri(azami: int = 40000) -> List[Ornek]:
    """PhiUSIIL'den dengeli örneklem (label 1 = meşru, 0 = phishing)."""
    zf = zipfile.ZipFile(VERI_DIR / "phiusiil.zip")
    ad = next(n for n in zf.namelist() if n.endswith(".csv"))
    sayac: Dict[str, int] = {"temiz": 0, "phishing": 0}
    sinir = azami // 2
    ornekler: List[Ornek] = []
    with zf.open(ad) as f:
        for satir in csv.DictReader(io.TextIOWrapper(f, encoding="utf-8-sig", errors="replace")):
            etiket = "temiz" if satir["label"] == "1" else "phishing"
            url = satir["URL"]
            # Hash ile seç: dosya sırasından bağımsız, kararlı örneklem
            if int(hashlib.md5(url.encode()).hexdigest()[:6], 16) % 6 != 0 or sayac[etiket] >= sinir:
                continue
            sayac[etiket] += 1
            ornekler.append(Ornek(url, etiket, "url", "phiusiil", _bolum(url)))
    return ornekler


def ozet(ornekler: List[Ornek]) -> Dict[Tuple[str, str, str], int]:
    d: Dict[Tuple[str, str, str], int] = {}
    for o in ornekler:
        k = (o.kaynak, o.etiket, o.bolum)
        d[k] = d.get(k, 0) + 1
    return d


def mevcut_mu() -> bool:
    return all((VERI_DIR / ad).exists() for ad in KAYNAKLAR)


def yol(ad: str) -> Path:
    return VERI_DIR / ad
