"""Kalkan web servisi: tarama API'si, canlı uyarı akışı ve panel.

Çalıştırma:  uvicorn kalkan.main:app --host 127.0.0.1 --port 8765
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import bulk, config, service, store, watchers
from .alerts import yayinci
from .detectors.image import ocr_kullanilabilir
from .ml import model as ml_model
from .ml import url_model

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
STATIC = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.hazirla()
    yayinci.baglan(asyncio.get_running_loop())
    await asyncio.to_thread(ml_model.yukle)
    await asyncio.to_thread(url_model.yukle)
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


def _oku(dosya: UploadFile, sinir_mb: int) -> bytes:
    sinir = sinir_mb * 1024 * 1024
    veri = dosya.file.read(sinir + 1)
    if len(veri) > sinir:
        raise HTTPException(status_code=413, detail=f"Dosya {sinir_mb} MB sınırını aşıyor")
    return veri


class MetinIstek(BaseModel):
    icerik: str = Field(..., min_length=1, max_length=2_000_000)
    tur: str = Field("eposta", pattern="^(eposta|sms)$")


class UrlIstek(BaseModel):
    url: str = Field(..., min_length=3, max_length=8000)


class Form(BaseModel):
    action: str = Field("", max_length=2000)
    sifre: bool = False
    kart: bool = False


class SayfaIstek(BaseModel):
    url: str = Field(..., min_length=8, max_length=8000)
    baslik: str = Field("", max_length=500)
    metin: str = Field("", max_length=20000)
    formlar: List[Form] = Field(default_factory=list, max_length=50)


class IndirmeIstek(BaseModel):
    yol: str = Field(..., min_length=1, max_length=4000)
    url: str = Field("", max_length=8000)


@app.get("/", include_in_schema=False)
def panel() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/durum")
def durum() -> dict:
    return {
        "surum": "0.2.0",
        "llm": config.LLM_ENABLED,
        "virustotal": bool(config.VIRUSTOTAL_API_KEY),
        "webhook": bool(config.ALERT_WEBHOOK_URL),
        "klasor_izleme": config.WATCH_DIR or None,
        "imap_izleme": bool(config.IMAP_HOST and config.IMAP_USER),
        "ocr": ocr_kullanilabilir(),
        "url_modeli": url_model.yukle() is not None,
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
    return service.dosya_tara(_oku(dosya, config.MAX_DOSYA_MB), dosya.filename or "adsiz", kaynak="panel")


@app.post("/api/tara/gorsel", dependencies=[Depends(yetki)])
def tara_gorsel(dosya: UploadFile = File(...)) -> dict:
    return service.gorsel_tara(_oku(dosya, 15), dosya.filename or "gorsel", kaynak="panel")


@app.post("/api/tara/sayfa", dependencies=[Depends(yetki)])
def tara_sayfa(istek: SayfaIstek) -> dict:
    """Chrome eklentisi: açık sekmedeki sayfa. Sayfa metni kaydedilmez."""
    if not istek.url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Yalnızca http(s) sayfaları taranır")
    return service.sayfa_tara(istek.url, istek.baslik, istek.metin, [f.model_dump() for f in istek.formlar])


@app.post("/api/tara/indirme", dependencies=[Depends(yetki)])
def tara_indirme(istek: IndirmeIstek) -> dict:
    try:
        return service.indirme_tara(istek.yol, istek.url)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=413, detail=str(e))


@app.post("/api/toplu", dependencies=[Depends(yetki)])
def toplu_baslat(dosya: UploadFile = File(...)) -> dict:
    veri = _oku(dosya, config.MAX_TOPLU_MB)
    return {"id": bulk.baslat(dosya.filename or "toplu", veri)}


@app.get("/api/toplu/{is_id}", dependencies=[Depends(yetki)])
def toplu_durum(is_id: str, ozet: bool = False) -> dict:
    d = bulk.durum(is_id, ozet_only=ozet)
    if d is None:
        raise HTTPException(status_code=404, detail="İş bulunamadı")
    return d


@app.post("/api/toplu/{is_id}/iptal", dependencies=[Depends(yetki)])
def toplu_iptal(is_id: str) -> dict:
    return {"ok": bulk.iptal(is_id)}


@app.get("/api/toplu/{is_id}/csv", dependencies=[Depends(yetki)])
def toplu_csv(is_id: str) -> PlainTextResponse:
    metin = bulk.csv_uret(is_id)
    if metin is None:
        raise HTTPException(status_code=404, detail="İş bulunamadı")
    return PlainTextResponse("﻿" + metin, media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="kalkan_toplu_{is_id}.csv"'})


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


@app.get("/api/rapor", dependencies=[Depends(yetki)])
def rapor(gun: int = Query(30, ge=1, le=365)) -> dict:
    return store.rapor(gun)


@app.get("/api/disa-aktar.csv", dependencies=[Depends(yetki)])
def disa_aktar(gun: int = Query(30, ge=1, le=365)) -> PlainTextResponse:
    # Excel'in Türkçe karakterleri doğru açması için BOM eklenir
    return PlainTextResponse("﻿" + store.csv_disa_aktar(gun), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="kalkan_rapor_{gun}gun.csv"'})


@app.get("/api/dogruluk")
def dogruluk() -> Dict[str, Any]:
    """Depoyla gelen modellerin gerçek veri setlerindeki ölçüm sonucu (docs/DOGRULUK.md)."""
    for yol in (config.DATA_DIR / "degerlendirme_sonra.json", ml_model.PAKET_DIR / "degerlendirme.json"):
        if yol.exists():
            d = json.loads(yol.read_text(encoding="utf-8"))
            d.pop("hata_ornekleri", None)
            return d
    raise HTTPException(status_code=404, detail="Değerlendirme sonucu yok")


@app.get("/api/olaylar", dependencies=[Depends(yetki)])
async def olaylar(request: Request) -> StreamingResponse:
    """Server-Sent Events: her yeni kayıt anında panele iletilir."""
    kuyruk = yayinci.abone_ol()

    async def akis():
        try:
            yield "event: hazir\ndata: {}\n\n"
            while not await request.is_disconnected():
                try:
                    olay = await asyncio.wait_for(kuyruk.get(), timeout=15)
                    yield f"data: {json.dumps(olay, ensure_ascii=False)}\n\n"
                except asyncio.TimeoutError:
                    yield ": canli\n\n"
        finally:
            yayinci.ayril(kuyruk)

    return StreamingResponse(akis(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})
