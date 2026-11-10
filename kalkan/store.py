"""SQLite tarama kaydı. İçeriğin tamamı değil, kısa etiket ve bulgular saklanır."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
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
        toplam = con.execute("SELECT COUNT(*) FROM taramalar").fetchone()[0]
        seviye = {r[0]: r[1] for r in con.execute("SELECT seviye, COUNT(*) FROM taramalar GROUP BY seviye")}
        kategori = {r[0]: r[1] for r in con.execute(
            "SELECT kategori, COUNT(*) FROM taramalar WHERE seviye != 'guvenli' GROUP BY kategori")}
        okunmamis = con.execute(
            "SELECT COUNT(*) FROM taramalar WHERE seviye != 'guvenli' AND okundu = 0").fetchone()[0]
    return {"toplam": toplam, "seviye": seviye, "kategori": kategori, "okunmamis_uyari": okunmamis}
