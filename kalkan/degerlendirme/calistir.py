"""Doğruluk ölçümü ve model eğitimi.

    python -m kalkan.degerlendirme.calistir --indir                 # veri setlerini indir
    python -m kalkan.degerlendirme.calistir --etiket once          # mevcut modellerle ölç
    python -m kalkan.degerlendirme.calistir --egit --etiket sonra  # eğitim bölmesiyle eğit, test bölmesinde ölç
    python -m kalkan.degerlendirme.calistir --egit --paket         # eğitilen modelleri depoya (kalkan/ml/modeller) kopyala

Ölçüm her zaman modelin eğitimde GÖRMEDİĞİ test bölmesinde yapılır.
"""
from __future__ import annotations

import argparse
import json
import shutil
import time
from collections import defaultdict
from typing import Dict, List, Optional

from .. import config
from ..detectors.text import metin_analiz, ml_metni
from ..detectors.url import url_analiz
from ..ml import model as metin_model
from ..ml import url_model
from ..models import kural_puani
from . import rapor, veri

MODLAR = ("kural", "ml", "hibrit")
ML_KODLARI = {"ml_metin", "ml_url"}


def _tahminler(sonuc, ml_tehdit: Optional[float]) -> Dict[str, Optional[bool]]:
    """Aynı örnek için üç karar biçimi. True = tehdit dedi.

    kural: ML bulguları çıkarılmış hâli · ml: modelin 0,5 eşiğindeki ham kararı · hibrit: sistemin gerçek kararı
    """
    kural_bulgulari = [b for b in sonuc.bulgular if b.kod not in ML_KODLARI]
    kural = kural_puani(kural_bulgulari)
    k_karar = any(b.kritik for b in kural_bulgulari) or kural >= config.SUPHELI_ESIK
    ml_karar = None if ml_tehdit is None else ml_tehdit >= 0.5
    return {"kural": k_karar, "ml": ml_karar, "hibrit": sonuc.seviye != "guvenli"}


def _metrik(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    def bol(a, b):
        return round(a / b, 4) if b else None

    kesinlik, duyarlilik = bol(tp, tp + fp), bol(tp, tp + fn)
    f1 = round(2 * kesinlik * duyarlilik / (kesinlik + duyarlilik), 4) if kesinlik and duyarlilik else None
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "dogruluk": bol(tp + tn, tp + fp + tn + fn),
        "kesinlik": kesinlik,  # "tehdit" dediklerinin ne kadarı gerçekten tehdit
        "tespit_orani": duyarlilik,  # gerçek tehditlerin ne kadarını yakaladı (recall)
        "yanlis_alarm": bol(fp, fp + tn),  # temiz içeriklerin ne kadarına alarm verdi (FPR)
        "f1": f1,
    }


def degerlendir(ornekler: List[veri.Ornek]) -> Dict[str, object]:
    sayac: Dict[str, Dict[str, List[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0, 0, 0]))
    kategori_dogru: Dict[str, List[int]] = defaultdict(lambda: [0, 0])
    sinyal_sayaci: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    hatalar: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    sure = 0.0

    for o in ornekler:
        t0 = time.perf_counter()
        if o.tur == "url":
            s = url_analiz(o.metin)
            ml_tehdit = s.ml["olasiliklar"].get("phishing") if s.ml else None
        else:
            s = metin_analiz(o.metin, tur=o.tur)
            ml_tehdit = (1 - s.ml["olasiliklar"].get("temiz", 0)) if s.ml else None
        sure += time.perf_counter() - t0

        gercek = o.etiket != "temiz"
        kararlar = _tahminler(s, ml_tehdit)
        for grup in (o.tur, f"{o.tur}:{o.kaynak}"):
            for mod, karar in kararlar.items():
                if karar is None:
                    continue
                h = sayac[grup][mod]
                h[0 if (gercek and karar) else 1 if karar else 2 if not gercek else 3] += 1

        etiket_grubu = f"{o.tur}:{o.etiket}"
        for b in s.bulgular:
            sinyal_sayaci[etiket_grubu][b.kod] += 1
        sinyal_sayaci[etiket_grubu]["_toplam"] += 1

        if gercek and s.seviye != "guvenli":
            kategori_dogru[o.tur][1] += 1
            if s.kategori == o.etiket:
                kategori_dogru[o.tur][0] += 1

        # Hata örnekleri: yalnızca kısa ve maskeli önizleme (kişisel veri raporda yer almasın)
        if gercek != (s.seviye != "guvenli") and len(hatalar[o.tur]) < 400:
            hatalar[o.tur].append({
                "tip": "kacirilan" if gercek else "yanlis_alarm",
                "kaynak": o.kaynak, "puan": s.puan, "hedef": s.hedef if o.tur == "url" else s.hedef[:60],
                "bulgular": [b.kod for b in s.bulgular],
            })

    sonuc = {
        "metrikler": {g: {m: _metrik(*v) for m, v in mods.items()} for g, mods in sayac.items()},
        "kategori_dogrulugu": {t: round(d / n, 4) if n else None for t, (d, n) in kategori_dogru.items()},
        "sinyaller": {g: dict(v) for g, v in sinyal_sayaci.items()},
        "hata_ornekleri": {t: v[:15] for t, v in hatalar.items()},
        "ortalama_ms": round(sure / max(len(ornekler), 1) * 1000, 2),
        "ornek_sayisi": len(ornekler),
    }
    return sonuc


def egit(egitim: List[veri.Ornek]) -> Dict[str, int]:
    metinler = [ml_metni(o.metin, o.tur) for o in egitim if o.tur != "url"]
    etiketler = [o.etiket for o in egitim if o.tur != "url"]
    tm, te = metin_model.veri_oku(metin_model.SEED_CSV)  # Türkçe örnekler azınlıkta kalmasın
    metinler += tm * 3
    etiketler += te * 3
    print(f"Metin modeli eğitiliyor: {len(metinler)} örnek")
    metin_model.egit(metinler, etiketler)

    urller = [o.metin for o in egitim if o.tur == "url"]
    print(f"URL modeli eğitiliyor: {len(urller)} örnek")
    url_model.egit(urller, [o.etiket for o in egitim if o.tur == "url"])
    return {"metin": len(metinler), "url": len(urller)}


def main() -> None:
    ap = argparse.ArgumentParser(description="Kalkan doğruluk ölçümü")
    ap.add_argument("--indir", action="store_true", help="Veri setlerini indir")
    ap.add_argument("--egit", action="store_true", help="Eğitim bölmesiyle modelleri yeniden eğit")
    ap.add_argument("--paket", action="store_true", help="Eğitilen modelleri kalkan/ml/modeller altına kopyala")
    ap.add_argument("--etiket", default="guncel", help="Sonuç etiketi (ör. once, sonra)")
    ap.add_argument("--url-sayisi", type=int, default=40000)
    args = ap.parse_args()

    if args.indir or not veri.mevcut_mu():
        veri.indir()

    print("Veri yükleniyor…")
    ornekler = veri.metin_ornekleri() + veri.url_ornekleri(args.url_sayisi)
    egitim = [o for o in ornekler if o.bolum == "egitim"]
    test = [o for o in ornekler if o.bolum == "test"]
    print(f"Eğitim: {len(egitim)}  Test: {len(test)}")

    egitim_bilgisi = None
    if args.egit:
        egitim_bilgisi = egit(egitim)
        if args.paket:
            metin_model.PAKET_DIR.mkdir(exist_ok=True)
            for ad in (metin_model.DOSYA, url_model.DOSYA):
                shutil.copy2(config.DATA_DIR / ad, metin_model.PAKET_DIR / ad)
            print(f"Modeller kopyalandı: {metin_model.PAKET_DIR}")

    print("Test bölmesi değerlendiriliyor…")
    sonuc = degerlendir(test)
    sonuc.update({
        "etiket": args.etiket,
        "tarih": time.strftime("%Y-%m-%d %H:%M"),
        "veri_ozeti": [{"kaynak": k, "etiket": e, "bolum": b, "sayi": n} for (k, e, b), n in sorted(veri.ozet(ornekler).items())],
        "egitim": egitim_bilgisi,
        "ayarlar": {"supheli_esik": config.SUPHELI_ESIK, "metin_ml_esik": config.METIN_ML_ESIK,
                    "url_ml_esik": config.URL_ML_ESIK},
    })
    yol = config.DATA_DIR / f"degerlendirme_{args.etiket}.json"
    yol.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Sonuç: {yol}")
    rapor.konsola_yaz(sonuc)
    if args.paket:
        # Depoya giden kopyada hata örnekleri yok: veri setlerinde gerçek kişilerin ad ve adresleri geçebiliyor (KVKK)
        paket = {k: v for k, v in sonuc.items() if k != "hata_ornekleri"}
        (metin_model.PAKET_DIR / "degerlendirme.json").write_text(
            json.dumps(paket, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
