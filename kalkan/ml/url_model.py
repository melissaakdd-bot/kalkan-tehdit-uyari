"""URL sınıflandırıcı (temiz / phishing): URL metni üzerinde karakter n-gram + lojistik regresyon.

Kural motoru yalnızca bilinen markaların taklidini yakalayabilir; bu model, PhiUSIIL gibi geniş bir
veri setinden alan adı ve yol yapısındaki genel phishing kalıplarını öğrenir.
"""
from __future__ import annotations

import threading
from typing import Dict, List, Optional

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .. import config
from .model import PAKET_DIR

_kilit = threading.Lock()
_model: Optional[Pipeline] = None
_yuklendi = False

DOSYA = "url_modeli.joblib"


def normalize(url: str) -> str:
    """Modele yalnızca alan adı verilir (şema, 'www.', yol ve sorgu atılır).

    Neden: PhiUSIIL'deki meşru URL'lerin neredeyse tamamı ana sayfa, phishing URL'lerinin çoğu yol içeriyor.
    Yol görülürse model "yol varsa phishing" kestirmesini öğreniyor ve github.com/x gibi adreslere
    %90+ phishing diyordu. Yalnızca alan adıyla eğitim bu kestirmeyi ortadan kaldırır.
    """
    u = url.strip().lower()
    if "://" in u:
        u = u.split("://", 1)[1]
    u = u.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    u = u.rsplit("@", 1)[-1].split(":", 1)[0]
    if u.startswith("www."):
        u = u[4:]
    return u.rstrip(".")


def pipeline_olustur() -> Pipeline:
    return Pipeline([
        ("ozellik", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), lowercase=True, sublinear_tf=True,
                                    min_df=2, max_features=300_000)),
        ("siniflandirici", LogisticRegression(max_iter=3000, C=4.0, class_weight="balanced")),
    ])


def egit(urller: List[str], etiketler: List[str], kaydet: bool = True) -> Pipeline:
    global _model, _yuklendi
    model = pipeline_olustur().fit([normalize(u) for u in urller], etiketler)
    if kaydet:
        joblib.dump(model, config.DATA_DIR / DOSYA, compress=3)
    with _kilit:
        _model, _yuklendi = model, True
    return model


def yukle() -> Optional[Pipeline]:
    global _model, _yuklendi
    with _kilit:
        if _yuklendi:
            return _model
        for yol in (config.DATA_DIR / DOSYA, PAKET_DIR / DOSYA):
            if yol.exists():
                _model = joblib.load(yol)
                break
        _yuklendi = True
        return _model


def sifirla() -> None:
    """Testler ve değerlendirme için önbelleği temizler."""
    global _model, _yuklendi
    with _kilit:
        _model, _yuklendi = None, False


def tahmin_et(url: str) -> Optional[Dict[str, object]]:
    model = yukle()
    if model is None:
        return None
    olasiliklar = model.predict_proba([normalize(url)])[0]
    sozluk = {s: round(float(p), 3) for s, p in zip(model.classes_, olasiliklar)}
    return {"etiket": max(sozluk.items(), key=lambda kv: kv[1])[0], "olasiliklar": sozluk}
