"""Görsel analizi: QR kod içindeki bağlantıyı ve (Tesseract kuruluysa) ekran görüntüsündeki yazıyı tarar.

QR oltalaması (quishing): saldırgan bağlantıyı bir görselin içine koyar; e-posta filtreleri metni
göremediği için mesaj içindeki bağlantı denetiminden kaçar.
"""
from __future__ import annotations

import re
import shutil
from typing import List, Optional

from ..models import Bulgu, Sonuc, sonuclandir
from .text import metin_analiz
from .url import url_analiz


def ocr_kullanilabilir() -> bool:
    try:
        import pytesseract  # noqa: F401
    except ImportError:
        return False
    return shutil.which("tesseract") is not None


def _qr_coz(veri: bytes) -> List[str]:
    import cv2
    import numpy as np

    img = cv2.imdecode(np.frombuffer(veri, np.uint8), cv2.IMREAD_GRAYSCALE)
    if img is None:
        return []
    # Çok büyük ekran görüntülerini küçült, küçük QR'ları büyüt
    h, w = img.shape[:2]
    if max(h, w) > 2400:
        o = 2400 / max(h, w)
        img = cv2.resize(img, None, fx=o, fy=o)
    bulunan: List[str] = []
    d = cv2.QRCodeDetector()
    for goruntu in (img, cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_NEAREST)):
        try:
            ok, metinler, *_ = d.detectAndDecodeMulti(goruntu)
        except cv2.error:
            ok, metinler = False, ()
        if ok:
            bulunan += [m for m in metinler if m and m not in bulunan]
        if bulunan:
            break
    return bulunan


def _ocr(veri: bytes) -> Optional[str]:
    if not ocr_kullanilabilir():
        return None
    import cv2
    import numpy as np
    import pytesseract

    img = cv2.imdecode(np.frombuffer(veri, np.uint8), cv2.IMREAD_GRAYSCALE)
    if img is None:
        return None
    try:
        diller = "tur+eng" if "tur" in pytesseract.get_languages(config="") else "eng"
        return pytesseract.image_to_string(img, lang=diller)
    except Exception:
        return None


def gorsel_analiz(veri: bytes, ad: str, kaynak: str = "panel") -> Sonuc:
    sonuc = Sonuc("gorsel", ad[:200], kaynak=kaynak)
    bulgular: List[Bulgu] = []
    qrlar = _qr_coz(veri)
    sonuc.ek["qr"] = []
    for icerik in qrlar[:5]:
        if re.match(r"(?i)^(https?://|www\.)", icerik.strip()):
            u = url_analiz(icerik.strip(), kaynak=kaynak)
            sonuc.ek["qr"].append({"icerik": icerik[:300], "tur": "baglanti", "puan": u.puan, "seviye": u.seviye,
                                   "bulgular": [b.aciklama for b in u.bulgular]})
            bulgular.append(Bulgu("qr_baglanti", f"QR kod bir bağlantı içeriyor: {u.ek.get('host', '')}.", 10, "phishing"))
            if u.seviye != "guvenli":
                bulgular.append(Bulgu("qr_riskli", f"QR koddaki bağlantı riskli (puan {u.puan}).",
                                      min(u.puan, 90), "phishing", kritik=any(b.kritik for b in u.bulgular)))
        else:
            m = metin_analiz(icerik, tur="sms", kaynak=kaynak)
            sonuc.ek["qr"].append({"icerik": icerik[:300], "tur": "metin", "puan": m.puan, "seviye": m.seviye})
            if m.seviye != "guvenli":
                bulgular.append(Bulgu("qr_metin_riskli", f"QR kod içindeki metin riskli (puan {m.puan}).", m.puan, m.kategori))

    metin = _ocr(veri)
    sonuc.ek["ocr"] = metin is not None
    if metin and metin.strip():
        m = metin_analiz(metin, tur="sms", kaynak=kaynak)
        sonuc.ek["ocr_ozet"] = m.hedef
        for b in m.bulgular:
            b.aciklama = "Görseldeki yazı: " + b.aciklama
            bulgular.append(b)
        if m.ml:
            sonuc.ml = m.ml
    sonuc.bulgular = bulgular
    return sonuclandir(sonuc)
