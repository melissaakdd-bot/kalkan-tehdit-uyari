"""Toplu tarama: .mbox, .eml, .eml içeren .zip ve URL listesi (.txt / .csv).

Arka planda iş olarak çalışır; ilerleme /api/toplu/{id} ile izlenir. Uyarı üreten sonuçlar geçmişe
kaydedilir, temiz olanlar yalnızca iş özetinde kalır (geçmiş binlerce satırla dolmasın).

Komut satırından:  python -m kalkan.bulk dosya.mbox
"""
from __future__ import annotations

import csv
import io
import mailbox
import os
import re
import tempfile
import threading
import time
import uuid
import zipfile
from typing import Any, Dict, Iterator, List, Optional, Tuple

AZAMI_OGE = 20000
_isler: Dict[str, Dict[str, Any]] = {}
_kilit = threading.Lock()


def _bayt_coz(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin-1")


def ogeler(ad: str, veri: bytes) -> Iterator[Tuple[str, str]]:
    """(tur, icerik) çiftleri üretir. tur: eposta | url"""
    ad_k = ad.lower()
    if ad_k.endswith(".mbox") or veri[:5] == b"From ":
        with tempfile.NamedTemporaryFile(suffix=".mbox", delete=False) as tmp:
            tmp.write(veri)
            yol = tmp.name
        try:
            for msg in mailbox.mbox(yol):
                yield "eposta", _bayt_coz(msg.as_bytes())
        finally:
            os.unlink(yol)
    elif ad_k.endswith(".eml"):
        yield "eposta", _bayt_coz(veri)
    elif ad_k.endswith(".zip"):
        zf = zipfile.ZipFile(io.BytesIO(veri))
        for bilgi in zf.infolist():
            # Arşivden açmadan okunur; boyut sınırı zip bombasına karşı
            if bilgi.is_dir() or bilgi.file_size > 25 * 1024 * 1024:
                continue
            ic = bilgi.filename.lower()
            if ic.endswith(".eml"):
                yield "eposta", _bayt_coz(zf.read(bilgi))
            elif ic.endswith((".txt", ".csv")):
                yield from ogeler(ic, zf.read(bilgi))
    elif ad_k.endswith((".txt", ".csv")):
        metin = _bayt_coz(veri)
        for satir in csv.reader(io.StringIO(metin)):
            for hucre in satir:
                h = hucre.strip()
                if re.match(r"(?i)^(https?://|www\.)\S+$", h) or re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/\S*)?$", h):
                    yield "url", h
    else:
        raise ValueError("Desteklenen biçimler: .mbox, .eml, .zip (.eml içeren), .txt / .csv (URL listesi)")


def _calistir(is_id: str, ad: str, veri: bytes, kaynak: str) -> None:
    from . import service

    is_ = _isler[is_id]
    try:
        liste = list(ogeler(ad, veri))[:AZAMI_OGE]
    except (ValueError, zipfile.BadZipFile) as e:
        is_.update(durum="hata", hata=str(e))
        return
    is_["toplam"] = len(liste)
    for tur, icerik in liste:
        if is_.get("iptal"):
            is_["durum"] = "iptal"
            return
        try:
            if tur == "url":
                k = service.url_tara(icerik, kaynak=kaynak, yalniz_uyari_kaydet=True)
            else:
                k = service.metin_tara(icerik, "eposta", kaynak=kaynak, yalniz_uyari_kaydet=True)
            is_["sonuclar"].append({"tur": k["tur"], "hedef": k["hedef"], "puan": k["puan"],
                                    "seviye": k["seviye"], "kategori": k["kategori"],
                                    "nedenler": [b["aciklama"] for b in sorted(k["bulgular"], key=lambda b: -b["agirlik"])[:3]]})
        except Exception as e:  # tek bir bozuk öğe tüm işi durdurmasın
            is_["sonuclar"].append({"tur": tur, "hedef": "(okunamadı)", "puan": 0, "seviye": "hata",
                                    "kategori": "", "nedenler": [type(e).__name__]})
        is_["islenen"] += 1
    is_["durum"] = "bitti"
    is_["bitis"] = time.time()


def baslat(ad: str, veri: bytes, kaynak: str = "toplu") -> str:
    is_id = uuid.uuid4().hex[:12]
    with _kilit:
        # Bellekte en fazla 20 iş tut
        if len(_isler) >= 20:
            eski = sorted(_isler, key=lambda k: _isler[k]["baslangic"])[0]
            _isler.pop(eski, None)
        _isler[is_id] = {"id": is_id, "ad": ad, "durum": "calisiyor", "toplam": None, "islenen": 0,
                         "sonuclar": [], "baslangic": time.time(), "bitis": None}
    threading.Thread(target=_calistir, args=(is_id, ad, veri, kaynak), daemon=True).start()
    return is_id


def durum(is_id: str, ozet_only: bool = False) -> Optional[Dict[str, Any]]:
    is_ = _isler.get(is_id)
    if not is_:
        return None
    sonuclar = is_["sonuclar"]
    sayac: Dict[str, int] = {}
    for s in sonuclar:
        sayac[s["seviye"]] = sayac.get(s["seviye"], 0) + 1
    d = {k: v for k, v in is_.items() if k != "sonuclar"}
    d["sayac"] = sayac
    if not ozet_only:
        d["sonuclar"] = sorted(sonuclar, key=lambda s: -s["puan"])
    return d


def iptal(is_id: str) -> bool:
    if is_id in _isler:
        _isler[is_id]["iptal"] = True
        return True
    return False


def csv_uret(is_id: str) -> Optional[str]:
    d = durum(is_id)
    if not d:
        return None
    tampon = io.StringIO()
    w = csv.writer(tampon)
    w.writerow(["tur", "hedef", "puan", "seviye", "kategori", "nedenler"])
    for s in d["sonuclar"]:
        w.writerow([s["tur"], s["hedef"], s["puan"], s["seviye"], s["kategori"], " | ".join(s["nedenler"])])
    return tampon.getvalue()


def main() -> None:
    import argparse
    import json

    from . import config, store

    ap = argparse.ArgumentParser(description="Kalkan toplu tarama")
    ap.add_argument("dosya")
    ap.add_argument("--csv", help="Sonuçları bu CSV dosyasına yaz")
    args = ap.parse_args()
    config.LLM_ENABLED = False  # toplu taramada dış API çağrılmaz
    store.hazirla()
    with open(args.dosya, "rb") as f:
        veri = f.read()
    is_id = baslat(os.path.basename(args.dosya), veri, kaynak="toplu")
    while _isler[is_id]["durum"] == "calisiyor":
        time.sleep(0.5)
        i = _isler[is_id]
        print(f"\r{i['islenen']}/{i['toplam'] or '?'}", end="", flush=True)
    print()
    d = durum(is_id)
    print(json.dumps({"durum": d["durum"], "toplam": d["toplam"], "sayac": d["sayac"]}, ensure_ascii=False))
    for s in d["sonuclar"][:20]:
        if s["seviye"] in ("supheli", "tehlikeli"):
            print(f"{s['puan']:3} {s['seviye']:9} {s['kategori']:9} {s['hedef'][:70]}")
    if args.csv:
        with open(args.csv, "w", encoding="utf-8", newline="") as f:
            f.write(csv_uret(is_id) or "")
        print(f"CSV yazıldı: {args.csv}")


if __name__ == "__main__":
    main()
