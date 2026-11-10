"""Uyarı dağıtımı: panele canlı akış (SSE) ve isteğe bağlı webhook (Slack/Teams)."""
from __future__ import annotations

import asyncio
import json
import logging
import threading
import urllib.request
from typing import Any, Dict, List, Optional

from . import config

log = logging.getLogger("kalkan.alerts")

ETIKET = {"supheli": "⚠️ ŞÜPHELİ", "tehlikeli": "🚨 TEHLİKELİ"}
KATEGORI = {"phishing": "Oltalama (phishing)", "spam": "Spam", "zararli": "Zararlı yazılım", "supheli": "Şüpheli içerik"}


class Yayinci:
    """Thread'lerden (klasör/IMAP izleyici) gelen olayları asyncio kuyruklarına güvenle iletir."""

    def __init__(self) -> None:
        self._abone: List[asyncio.Queue] = []
        self._dongu: Optional[asyncio.AbstractEventLoop] = None
        self._kilit = threading.Lock()

    def baglan(self, dongu: asyncio.AbstractEventLoop) -> None:
        self._dongu = dongu

    def abone_ol(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        with self._kilit:
            self._abone.append(q)
        return q

    def ayril(self, q: asyncio.Queue) -> None:
        with self._kilit:
            if q in self._abone:
                self._abone.remove(q)

    def yayinla(self, olay: Dict[str, Any]) -> None:
        if self._dongu is None:
            return
        with self._kilit:
            hedefler = list(self._abone)
        for q in hedefler:
            self._dongu.call_soon_threadsafe(self._koy, q, olay)

    @staticmethod
    def _koy(q: asyncio.Queue, olay: Dict[str, Any]) -> None:
        if q.full():
            q.get_nowait()
        q.put_nowait(olay)


yayinci = Yayinci()


def _webhook(kayit: Dict[str, Any]) -> None:
    if not config.ALERT_WEBHOOK_URL:
        return
    bulgular = "\n".join(f"• {b['aciklama']}" for b in kayit.get("bulgular", [])[:5])
    metin = (
        f"{ETIKET.get(kayit['seviye'], kayit['seviye'])} | {KATEGORI.get(kayit['kategori'], kayit['kategori'])}\n"
        f"Tür: {kayit['tur']} · Kaynak: {kayit['kaynak']} · Risk: {kayit['puan']}/100\n"
        f"Hedef: {kayit['hedef']}\n{bulgular}"
    )
    istek = urllib.request.Request(
        config.ALERT_WEBHOOK_URL, data=json.dumps({"text": metin}).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        urllib.request.urlopen(istek, timeout=10).close()
    except Exception as e:  # webhook hatası taramayı durdurmamalı
        log.warning("Webhook gönderilemedi: %s", e)


def bildir(kayit: Dict[str, Any]) -> None:
    """Her tarama panele akar; şüpheli ve tehlikeli olanlar ayrıca webhook ile gönderilir."""
    yayinci.yayinla({"tip": "tarama", "veri": kayit})
    if kayit["seviye"] != "guvenli":
        threading.Thread(target=_webhook, args=(kayit,), daemon=True).start()
