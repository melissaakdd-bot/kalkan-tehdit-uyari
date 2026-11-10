"""Kalkan web servisi: tarama API'si, canlı uyarı akışı ve panel.

Çalıştırma:  uvicorn kalkan.main:app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import config, service, store, watchers
from .alerts import yayinci
from .ml import model as ml_model

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
STATIC = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.hazirla()
    yayinci.baglan(asyncio.get_running_loop())
    await asyncio.to_thread(ml_model.yukle)
    watchers.baslat()
    yield
    watchers.durdur()


app = FastAPI(title="Kalkan", description="Yapay zekâ destekli tehdit uyarı sistemi", lifespan=lifespan)


def yetki(x_kalkan_token: Optional[str] = Header(default=None), token: Optional[str] = Query(default=None)) -> None:
    if not config.PANEL_TOKEN:
        return
    verilen = x_kalkan_token or token or ""
    if not hmac.compare_digest(verilen, config.PANEL_TOKEN):
        raise HTTPException(status_code=401, detail="Geçersiz ya da eksik erişim anahtarı")


class MetinIstek(BaseModel):
    icerik: str = Field(..., min_length=1, max_length=2_000_000)
    tur: str = Field("eposta", pattern="^(eposta|sms)$")


class UrlIstek(BaseModel):
    url: str = Field(..., min_length=3, max_length=8000)


@app.get("/", include_in_schema=False)
def panel() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/durum")
def durum() -> dict:
    return {
        "llm": config.LLM_ENABLED,
        "virustotal": bool(config.VIRUSTOTAL_API_KEY),
        "webhook": bool(config.ALERT_WEBHOOK_URL),
        "klasor_izleme": config.WATCH_DIR or None,
        "imap_izleme": bool(config.IMAP_HOST and config.IMAP_USER),
        "token_gerekli": bool(config.PANEL_TOKEN),
        "esikler": {"supheli": config.SUPHELI_ESIK, "tehlikeli": config.TEHLIKELI_ESIK},
    }


@app.post("/api/tara/metin", dependencies=[Depends(yetki)])
def tara_metin(istek: MetinIstek) -> dict:
    return service.metin_tara(istek.icerik, istek.tur, kaynak="panel")


@app.post("/api/tara/url", dependencies=[Depends(yetki)])
def tara_url(istek: UrlIstek) -> dict:
    return service.url_tara(istek.url, kaynak="panel")


@app.post("/api/tara/dosya", dependencies=[Depends(yetki)])
def tara_dosya(dosya: UploadFile = File(...)) -> dict:
    sinir = config.MAX_DOSYA_MB * 1024 * 1024
    veri = dosya.file.read(sinir + 1)
    if len(veri) > sinir:
        raise HTTPException(status_code=413, detail=f"Dosya {config.MAX_DOSYA_MB} MB sınırını aşıyor")
    return service.dosya_tara(veri, dosya.filename or "adsiz", kaynak="panel")


@app.get("/api/gecmis", dependencies=[Depends(yetki)])
def gecmis(limit: int = Query(100, ge=1, le=1000), sadece_uyari: bool = False) -> list:
    return store.listele(limit, sadece_uyari)


@app.post("/api/gecmis/{kayit_id}/okundu", dependencies=[Depends(yetki)])
def okundu(kayit_id: int) -> dict:
    store.okundu_isaretle(kayit_id)
    return {"ok": True}


@app.get("/api/istatistik", dependencies=[Depends(yetki)])
def istatistik() -> dict:
    return store.istatistik()


@app.get("/api/olaylar", dependencies=[Depends(yetki)])
async def olaylar(request: Request) -> StreamingResponse:
    """Server-Sent Events: her yeni tarama anında panele iletilir."""
    kuyruk = yayinci.abone_ol()

    async def akis():
        try:
            yield "event: hazir\ndata: {}\n\n"
            while not await request.is_disconnected():
                try:
                    olay = await asyncio.wait_for(kuyruk.get(), timeout=15)
                    yield f"data: {json.dumps(olay, ensure_ascii=False)}\n\n"
                except asyncio.TimeoutError:
                    yield ": canli\n\n"  # bağlantıyı açık tut
        finally:
            yayinci.ayril(kuyruk)

    return StreamingResponse(akis(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})
