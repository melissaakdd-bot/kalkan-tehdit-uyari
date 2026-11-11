"""SQLite tarama kaydı. İçeriğin tamamı değil, kısa etiket ve bulgular saklanır."""
from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
import threading
import time
from collections import Counter
from typing import Any, Dict, List

from . import config
from .models import Sonuc

_kilit = threading.Lock()


def _baglan() -> sqlite3.Connection:
    con = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def hazirla() -> None:
    with _kilit, _baglan() as con:
        con.execute(
            """CREATE TABLE IF NOT EXISTS taramalar (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                zaman REAL NOT NULL,
                tur TEXT NOT NULL,
                kaynak TEXT NOT NULL,
                hedef TEXT NOT NULL,
                puan INTEGER NOT NULL,
                seviye TEXT NOT NULL,
                kategori TEXT NOT NULL,
                detay TEXT NOT NULL,
                okundu INTEGER NOT NULL DEFAULT 0
            )"""
        )
        con.execute("CREATE INDEX IF NOT EXISTS ix_zaman ON taramalar(zaman DESC)")
        # Günlük tarama sayaçları: temiz sonuçları tek tek saklamadan "kaç şey tarandı" sorusunu yanıtlar
        con.execute(
            """CREATE TABLE IF NOT EXISTS sayaclar (
                gun TEXT NOT NULL, tur TEXT NOT NULL, seviye TEXT NOT NULL, sayi INTEGER NOT NULL,
                PRIMARY KEY (gun, tur, seviye)
            )"""
        )


def say(tur: str, seviye: str) -> None:
    gun = time.strftime("%Y-%m-%d")
    with _kilit, _baglan() as con:
        con.execute(
            "INSERT INTO sayaclar (gun, tur, seviye, sayi) VALUES (?,?,?,1) "
            "ON CONFLICT(gun, tur, seviye) DO UPDATE SET sayi = sayi + 1",
            (gun, tur, seviye),
        )


def kaydet(sonuc: Sonuc) -> Dict[str, Any]:
    d = sonuc.to_dict()
    zaman = time.time()
    with _kilit, _baglan() as con:
        cur = con.execute(
            "INSERT INTO taramalar (zaman, tur, kaynak, hedef, puan, seviye, kategori, detay) VALUES (?,?,?,?,?,?,?,?)",
            (zaman, sonuc.tur, sonuc.kaynak, sonuc.hedef, sonuc.puan, sonuc.seviye, sonuc.kategori,
             json.dumps(d, ensure_ascii=False)),
        )
        d["id"] = cur.lastrowid
    d["zaman"] = zaman
    return d


def _satir(r: sqlite3.Row) -> Dict[str, Any]:
    d = json.loads(r["detay"])
    d.update({"id": r["id"], "zaman": r["zaman"], "okundu": bool(r["okundu"])})
    return d


def listele(limit: int = 100, sadece_uyari: bool = False) -> List[Dict[str, Any]]:
    sorgu = "SELECT * FROM taramalar"
    if sadece_uyari:
        sorgu += " WHERE seviye != 'guvenli'"
    sorgu += " ORDER BY zaman DESC LIMIT ?"
    with _kilit, _baglan() as con:
        return [_satir(r) for r in con.execute(sorgu, (limit,))]


def okundu_isaretle(kayit_id: int) -> None:
    with _kilit, _baglan() as con:
        con.execute("UPDATE taramalar SET okundu = 1 WHERE id = ?", (kayit_id,))


def istatistik() -> Dict[str, Any]:
    with _kilit, _baglan() as con:
        seviye = {r[0]: r[1] for r in con.execute("SELECT seviye, SUM(sayi) FROM sayaclar GROUP BY seviye")}
        okunmamis = con.execute(
            "SELECT COUNT(*) FROM taramalar WHERE seviye != 'guvenli' AND okundu = 0").fetchone()[0]
    return {"toplam": sum(seviye.values()), "seviye": seviye, "okunmamis_uyari": okunmamis}


SINYAL_ADLARI = {
    "ml_metin": "Yapay zekâ: metin tehdit örneklerine benziyor", "ml_url": "Yapay zekâ: alan adı phishing'e benziyor",
    "riskli_baglanti": "Riskli bağlantı", "baglanti_ve_talep": "Bağlantı + bilgi/ödeme talebi",
    "aciliyet": "Aciliyet ve baskı dili", "kimlik_bilgisi": "Şifre/kart/kod talebi", "hesap_tehdidi": "Hesap kapatma tehdidi",
    "odeme_talebi": "Ödeme/ücret talebi", "odul_vaadi": "Ödül, hediye vaadi", "pazarlama": "Toplu pazarlama dili",
    "reply_to_farkli": "Yanıt adresi farklı", "spf_fail": "SPF doğrulaması başarısız", "dkim_fail": "DKIM doğrulaması başarısız",
    "dmarc_fail": "DMARC doğrulaması başarısız", "gorunen_ad_taklidi": "Gönderen adında kurum taklidi",
    "marka_baglanti_uyumsuz": "Marka adına yazılmış, bağlantı başka yere", "marka_taklidi": "Adreste marka taklidi",
    "yazim_taklidi": "Benzer yazımlı alan adı", "supheli_tld": "Şüpheli alan uzantısı", "kisaltici": "Kısaltılmış bağlantı",
    "kullanici_icerigi": "Ücretsiz barındırma servisi", "sahte_giris_sayfasi": "Sahte giriş sayfası",
    "form_baska_alana": "Şifre başka alana gönderiliyor", "cift_uzanti": "Çift uzantılı dosya",
    "gizli_calistirilabilir": "Belge kılığında program", "office_makro": "Office makrosu", "supheli_kod": "Şüpheli kod deseni",
    "eicar": "Antivirüs test imzası", "riskli_ek": "Riskli e-posta eki", "qr_riskli": "QR kodda riskli bağlantı",
    "unlem": "Çok sayıda ünlem", "zararli_ek": "Çalıştırılabilir ek isteği", "ip_host": "IP adresli bağlantı",
}

_MARKA_RE = re.compile(r"'([^']+)' (?:adı geçiyor|adını taşıyor|adına yazılmış)")


def rapor(gun: int = 30) -> Dict[str, Any]:
    """Panel grafikleri için özet: günlük tarama/uyarı, kategori, kaynak, en çok taklit edilen markalar."""
    baslangic = time.time() - gun * 86400
    bas_gun = time.strftime("%Y-%m-%d", time.localtime(baslangic))
    with _kilit, _baglan() as con:
        gunluk: Dict[str, Dict[str, int]] = {}
        for r in con.execute("SELECT gun, seviye, SUM(sayi) FROM sayaclar WHERE gun >= ? GROUP BY gun, seviye", (bas_gun,)):
            gunluk.setdefault(r[0], {"guvenli": 0, "supheli": 0, "tehlikeli": 0})[r[1]] = r[2]
        turler = {r[0]: r[1] for r in con.execute(
            "SELECT tur, SUM(sayi) FROM sayaclar WHERE gun >= ? GROUP BY tur", (bas_gun,))}
        uyarilar = list(con.execute(
            "SELECT tur, kaynak, kategori, detay FROM taramalar WHERE zaman >= ? AND seviye != 'guvenli'", (baslangic,)))
    kategori: Counter = Counter()
    kaynak: Counter = Counter()
    marka: Counter = Counter()
    sinyal: Counter = Counter()
    for r in uyarilar:
        kategori[r["kategori"]] += 1
        kaynak[r["kaynak"]] += 1
        d = json.loads(r["detay"])
        markalar = set()
        for b in d.get("bulgular", []):
            sinyal[SINYAL_ADLARI.get(b["kod"], b["kod"])] += 1
            m = _MARKA_RE.search(b["aciklama"])
            if m:
                markalar.add(m.group(1))
        marka.update(markalar)
    gunler = []
    for i in range(gun - 1, -1, -1):
        g = time.strftime("%Y-%m-%d", time.localtime(time.time() - i * 86400))
        gunler.append({"gun": g, **gunluk.get(g, {"guvenli": 0, "supheli": 0, "tehlikeli": 0})})
    return {
        "gun": gun,
        "gunluk": gunler,
        "tur": turler,
        "kategori": dict(kategori.most_common()),
        "kaynak": dict(kaynak.most_common()),
        "markalar": dict(marka.most_common(8)),
        "sinyaller": dict(sinyal.most_common(8)),
        "uyari_sayisi": len(uyarilar),
    }


def csv_disa_aktar(gun: int = 30) -> str:
    baslangic = time.time() - gun * 86400
    tampon = io.StringIO()
    w = csv.writer(tampon)
    w.writerow(["zaman", "tur", "kaynak", "hedef", "puan", "seviye", "kategori", "nedenler"])
    with _kilit, _baglan() as con:
        for r in con.execute("SELECT * FROM taramalar WHERE zaman >= ? ORDER BY zaman DESC", (baslangic,)):
            d = json.loads(r["detay"])
            nedenler = " | ".join(b["aciklama"] for b in sorted(d.get("bulgular", []), key=lambda b: -b["agirlik"])[:4])
            w.writerow([time.strftime("%Y-%m-%d %H:%M", time.localtime(r["zaman"])), r["tur"], r["kaynak"],
                        r["hedef"], r["puan"], r["seviye"], r["kategori"], nedenler])
    return tampon.getvalue()
