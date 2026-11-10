"""Metin sınıflandırıcı (temiz / spam / phishing): TF-IDF karakter n-gram + lojistik regresyon.

Karakter n-gram, Türkçe eklerine ve kasıtlı yazım bozmalarına (ş1fre, h3sap) kelime tabanlı modelden dayanıklıdır.
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
        ("karakter", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), lowercase=True, sublinear_tf=True, min_df=1)),
        ("kelime", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), lowercase=True, sublinear_tf=True, token_pattern=r"(?u)\b\w+\b")),
    ])
    return Pipeline([
        ("ozellik", ozellikler),
        ("siniflandirici", LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")),
    ])


def egit(metinler: List[str], etiketler: List[str], kaydet: bool = True) -> Pipeline:
    global _model
    model = pipeline_olustur().fit(metinler, etiketler)
    if kaydet:
        joblib.dump(model, config.MODEL_PATH)
    with _kilit:
        _model = model
    return model


def yukle() -> Optional[Pipeline]:
    """Kayıtlı model yoksa tohum veriyle eğitir."""
    global _model
    with _kilit:
        if _model is not None:
            return _model
    if config.MODEL_PATH.exists():
        model = joblib.load(config.MODEL_PATH)
        with _kilit:
            _model = model
        return model
    if SEED_CSV.exists():
        return egit(*veri_oku(SEED_CSV))
    return None


def tahmin_et(metin: str) -> Optional[Dict[str, object]]:
    model = yukle()
    if model is None or not metin.strip():
        return None
    olasiliklar = model.predict_proba([metin[:20000]])[0]
    siniflar = list(model.classes_)
    sozluk = {s: round(float(p), 3) for s, p in zip(siniflar, olasiliklar)}
    etiket = max(sozluk.items(), key=lambda kv: kv[1])[0]
    return {"etiket": etiket, "olasiliklar": sozluk}
