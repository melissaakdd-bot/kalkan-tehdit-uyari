"""Metin sınıflandırıcı (temiz / spam / phishing): TF-IDF karakter + kelime n-gram ve lojistik regresyon.

Karakter n-gram, Türkçe eklerine ve kasıtlı yazım bozmalarına (ş1fre, h3sap) kelime tabanlı modelden dayanıklıdır.

Model arama sırası: data/metin_modeli.joblib (yerel eğitim) -> kalkan/ml/modeller/ (depoyla gelen,
gerçek veriyle eğitilmiş) -> tohum veriyle anında eğitim.
"""
from __future__ import annotations

import csv
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from .. import config

SEED_CSV = Path(__file__).with_name("tohum_veri.csv")
PAKET_DIR = Path(__file__).with_name("modeller")
DOSYA = "metin_modeli.joblib"
_kilit = threading.Lock()
_model: Optional[Pipeline] = None


def veri_oku(yol: Path) -> Tuple[List[str], List[str]]:
    metinler, etiketler = [], []
    with open(yol, newline="", encoding="utf-8") as f:
        for satir in csv.DictReader(f):
            if satir.get("metin") and satir.get("etiket"):
                metinler.append(satir["metin"])
                etiketler.append(satir["etiket"].strip())
    return metinler, etiketler


def pipeline_olustur() -> Pipeline:
    ozellikler = FeatureUnion([
        ("karakter", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), lowercase=True, sublinear_tf=True,
                                     min_df=2, max_features=300_000)),
        ("kelime", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), lowercase=True, sublinear_tf=True,
                                   token_pattern=r"(?u)\b\w+\b", min_df=2, max_features=200_000)),
    ])
    return Pipeline([
        ("ozellik", ozellikler),
        ("siniflandirici", LogisticRegression(max_iter=3000, C=4.0, class_weight="balanced")),
    ])


def egit(metinler: List[str], etiketler: List[str], kaydet: bool = True) -> Pipeline:
    global _model
    metinler = [m[:20000] for m in metinler]
    pipe = pipeline_olustur()
    if len(metinler) < 200:  # tohum veri gibi küçük kümelerde min_df=2 sözlüğü fazla daraltır
        pipe.set_params(ozellik__karakter__min_df=1, ozellik__kelime__min_df=1)
    model = pipe.fit(metinler, etiketler)
    if kaydet:
        joblib.dump(model, config.DATA_DIR / DOSYA, compress=3)
    with _kilit:
        _model = model
    return model


def yukle() -> Optional[Pipeline]:
    global _model
    with _kilit:
        if _model is not None:
            return _model
    for yol in (config.DATA_DIR / DOSYA, PAKET_DIR / DOSYA):
        if yol.exists():
            model = joblib.load(yol)
            with _kilit:
                _model = model
            return model
    if SEED_CSV.exists():
        return egit(*veri_oku(SEED_CSV), kaydet=False)
    return None


def sifirla() -> None:
    global _model
    with _kilit:
        _model = None


def tahmin_et(metin: str) -> Optional[Dict[str, object]]:
    model = yukle()
    if model is None or not metin.strip():
        return None
    olasiliklar = model.predict_proba([metin[:20000]])[0]
    siniflar = list(model.classes_)
    sozluk = {s: round(float(p), 3) for s, p in zip(siniflar, olasiliklar)}
    etiket = max(sozluk.items(), key=lambda kv: kv[1])[0]
    return {"etiket": etiket, "olasiliklar": sozluk}
