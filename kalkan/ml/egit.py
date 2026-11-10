"""Modeli kendi verinizle yeniden eğitin.

Kullanım:
    python -m kalkan.ml.egit --csv veri.csv          # sütunlar: metin,etiket (temiz|spam|phishing)
    python -m kalkan.ml.egit --csv veri.csv --tohum  # kendi verinize tohum veriyi de ekler
"""
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from sklearn.metrics import classification_report
from sklearn.model_selection import StratifiedKFold, cross_val_predict

from .. import config
from .model import SEED_CSV, egit, pipeline_olustur, veri_oku


def main() -> None:
    ap = argparse.ArgumentParser(description="Kalkan metin modelini eğit")
    ap.add_argument("--csv", type=Path, help="metin,etiket sütunlu CSV")
    ap.add_argument("--tohum", action="store_true", help="Tohum veriyi de ekle")
    args = ap.parse_args()

    metinler, etiketler = [], []
    if args.csv:
        m, e = veri_oku(args.csv)
        metinler += m
        etiketler += e
    if args.tohum or not args.csv:
        m, e = veri_oku(SEED_CSV)
        metinler += m
        etiketler += e

    dagilim = Counter(etiketler)
    print(f"Örnek sayısı: {len(metinler)}  Dağılım: {dict(dagilim)}")
    kat = min(5, min(dagilim.values()))
    if kat >= 2:
        tahmin = cross_val_predict(pipeline_olustur(), metinler, etiketler, cv=StratifiedKFold(kat, shuffle=True, random_state=42))
        print(f"\n{kat} katlı çapraz doğrulama sonucu:")
        print(classification_report(etiketler, tahmin, digits=3, zero_division=0))
    egit(metinler, etiketler)
    print(f"Model kaydedildi: {config.MODEL_PATH}")


if __name__ == "__main__":
    main()
