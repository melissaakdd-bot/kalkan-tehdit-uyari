"""Kalkan web servisi: tarama API'si, canlı uyarı akışı ve panel.

Çalıştırma:  uvicorn kalkan.main:app --host 127.0.0.1 --port 8765
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import bulk, config, karantina, service, sistem_tarama, store, uygulamalar, watchers
from .alerts import yayinci
from .detectors.image import ocr_kullanilabilir
from .ml import model as ml_model
from .ml import url_model

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
STATIC = Path(__file__).resolve().parent.parent / "static"
# Panel (static/index.html) beklediği sürümü bilir; sunucu eski kodla çalışıyorsa uyarı gösterir.
# Uç nokta eklendiğinde ya da değiştiğinde ikisi birlikte artırılır.
SURUM = "0.5.0"


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


@app.middleware("http")
async def baska_site_koruma(request: Request, call_next):
    """Dışarıdan istek sahteciliğine (CSRF) karşı koruma.

    Tarayıcıda açık kötü niyetli bir site, kullanıcının bilgisayarındaki bu sunucuya form ile POST
    gönderebilir (ör. karantinadaki zararlıyı geri yükletmek, karantinayı boşaltmak). Değişiklik yapan
    isteklerde Origin başlığı varsa yalnızca panelin kendi adresi ve Chrome eklentisi kabul edilir.
    """
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        kaynak = request.headers.get("origin")
        if kaynak and kaynak != "null":
            izinli = kaynak.startswith("chrome-extension://") or kaynak.split("://", 1)[-1] == request.headers.get("host", "")
            if not izinli:
                return JSONResponse({"detail": "Başka bir siteden gelen istek reddedildi"}, status_code=403)
        elif kaynak == "null":
            return JSONResponse({"detail": "Kaynağı belirsiz istek reddedildi"}, status_code=403)
    return await call_next(request)


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
        "surum": SURUM,
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


class SistemIstek(BaseModel):
    tur: str = Field("hizli", pattern="^(hizli|tam|klasor)$")
    klasor: str = Field("", max_length=4000)


class KarantinaIstek(BaseModel):
    is_id: str = Field(..., pattern="^[a-f0-9]{12}$")
    no: int = Field(..., ge=0)


@app.post("/api/sistem/tara", dependencies=[Depends(yetki)])
def sistem_tara(istek: SistemIstek) -> dict:
    try:
        return {"id": sistem_tarama.baslat(istek.tur, istek.klasor or None)}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))


@app.get("/api/sistem/durum", dependencies=[Depends(yetki)])
def sistem_durum(is_id: Optional[str] = None) -> dict:
    d = sistem_tarama.durum(is_id) if is_id else sistem_tarama.son_is()
    return {
        "is": d,
        "son_tarama": sistem_tarama.son_tarama(),
        "otomatik_saat": config.OTOMATIK_TARAMA_SAAT,
        "hizli_konumlar": [str(k) for k, _ in sistem_tarama.hizli_konumlar()],
    }


@app.post("/api/sistem/{is_id}/iptal", dependencies=[Depends(yetki)])
def sistem_iptal(is_id: str) -> dict:
    return {"ok": sistem_tarama.iptal(is_id)}


@app.post("/api/karantina", dependencies=[Depends(yetki)])
def karantinaya_al(istek: KarantinaIstek) -> dict:
    """Yalnızca bir bilgisayar taramasının bulduğu dosya karantinaya alınabilir (keyfi yol kabul edilmez)."""
    b = sistem_tarama.bulgu(istek.is_id, istek.no)
    if b is None:
        raise HTTPException(status_code=404, detail="Tarama bulgusu bulunamadı")
    if b["tur"] != "dosya":
        raise HTTPException(status_code=400, detail="Başlangıç öğeleri karantinaya alınamaz; README'deki adımlarla kaldırın")
    try:
        meta = karantina.al(b["yol"], b.get("sha256"), b["nedenler"])
    except (FileNotFoundError, ValueError, PermissionError, OSError) as e:
        raise HTTPException(status_code=409, detail=str(e))
    b["karantina"] = meta["id"]
    return meta


def _bulgu_al(istek: "KarantinaIstek") -> Dict[str, Any]:
    b = sistem_tarama.bulgu(istek.is_id, istek.no)
    if b is None:
        raise HTTPException(status_code=404, detail="Tarama bulgusu bulunamadı")
    return b


@app.post("/api/sistem/goster", dependencies=[Depends(yetki)])
def bulguyu_goster(istek: KarantinaIstek) -> dict:
    """Bulunan dosyayı Finder'da (Windows'ta Gezgin'de) seçili gösterir."""
    b = _bulgu_al(istek)
    if b.get("karantina") or b.get("silindi"):
        raise HTTPException(status_code=409, detail="Dosya artık bu konumda değil")
    try:
        karantina.klasorde_goster(b["yol"])
    except FileNotFoundError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return {"ok": True}


@app.post("/api/sistem/cop", dependencies=[Depends(yetki)])
def cop_kutusuna(istek: KarantinaIstek) -> dict:
    """Bulunan dosyayı (ya da başlangıç öğesini) çöp kutusuna taşır. Kullanıcı oradan geri alabilir."""
    b = _bulgu_al(istek)
    try:
        nereye = karantina.cop_kutusuna_tasi(b["yol"], b.get("sha256"))
    except (FileNotFoundError, ValueError, PermissionError, OSError, subprocess.TimeoutExpired) as e:
        mesaj = str(e)
        if isinstance(e, PermissionError):
            mesaj = "İzin yok: sistem klasöründeki öğeler için yönetici izni gerekir (README → Bilgisayar taraması)"
        raise HTTPException(status_code=409, detail=mesaj)
    b["silindi"] = nereye
    return {"ok": True, "nereye": nereye}


class TemizleIstek(BaseModel):
    is_id: str = Field(..., pattern="^[a-f0-9]{12}$")
    seviye: str = Field("tehlikeli", pattern="^(tehlikeli|hepsi)$")


@app.post("/api/sistem/temizle", dependencies=[Depends(yetki)])
def temizle(istek: TemizleIstek) -> dict:
    """Taramada bulunan (tehlikeli ya da tüm riskli) dosyaları tek seferde karantinaya alır."""
    d = sistem_tarama.durum(istek.is_id)
    if d is None:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı")
    alinan, hatalar = 0, []
    for b in sistem_tarama._isler[istek.is_id]["bulgular"]:
        if b["tur"] != "dosya" or b.get("karantina") or b.get("silindi"):
            continue
        if istek.seviye == "tehlikeli" and b["seviye"] != "tehlikeli":
            continue
        try:
            b["karantina"] = karantina.al(b["yol"], b.get("sha256"), b["nedenler"])["id"]
            alinan += 1
        except (FileNotFoundError, ValueError, PermissionError, OSError) as e:
            hatalar.append({"yol": b["yol"], "hata": str(e)})
    return {"karantinaya_alinan": alinan, "hatalar": hatalar}


class KaldirIstek(BaseModel):
    artiklar: List[str] = Field(default_factory=list, max_length=200)


def _uygulama_destegi() -> None:
    if not uygulamalar.destekleniyor():
        raise HTTPException(status_code=400, detail="Uygulama yöneticisi yalnızca macOS'ta çalışır")


@app.get("/api/uygulamalar", dependencies=[Depends(yetki)])
def uygulama_listesi() -> dict:
    _uygulama_destegi()
    return uygulamalar.listele()


@app.get("/api/uygulamalar/{kimlik}/artiklar", dependencies=[Depends(yetki)])
def uygulama_artiklari(kimlik: str) -> dict:
    _uygulama_destegi()
    try:
        return uygulamalar.artiklar(kimlik)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))


@app.post("/api/uygulamalar/{kimlik}/kaldir", dependencies=[Depends(yetki)])
def uygulama_kaldir(kimlik: str, istek: KaldirIstek) -> dict:
    """Uygulamayı ve seçilen artıklarını Çöp Kutusu'na taşır. Yalnızca sunucunun bulduğu yollar kabul edilir."""
    _uygulama_destegi()
    try:
        return uygulamalar.kaldir(kimlik, istek.artiklar)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except (RuntimeError, PermissionError) as e:
        raise HTTPException(status_code=409, detail=str(e))


@app.post("/api/uygulamalar/{kimlik}/goster", dependencies=[Depends(yetki)])
def uygulama_goster(kimlik: str) -> dict:
    _uygulama_destegi()
    try:
        karantina.klasorde_goster(str(uygulamalar._bul(kimlik)))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"ok": True}


@app.get("/api/karantina", dependencies=[Depends(yetki)])
def karantina_listesi() -> list:
    return karantina.listele()


class OnayIstek(BaseModel):
    onay: bool = Field(..., description="Kalıcı silme için true olmalı")


@app.delete("/api/karantina/{kimlik}", dependencies=[Depends(yetki)])
def karantina_kalici_sil(kimlik: str) -> dict:
    try:
        return karantina.kalici_sil(kimlik)
    except (FileNotFoundError, ValueError, OSError) as e:
        raise HTTPException(status_code=409, detail=str(e))


@app.post("/api/karantina/bosalt", dependencies=[Depends(yetki)])
def karantina_bosalt(istek: OnayIstek) -> dict:
    if not istek.onay:
        raise HTTPException(status_code=400, detail="Onay gerekli")
    return {"silinen": karantina.bosalt()}


@app.post("/api/karantina/{kimlik}/goster", dependencies=[Depends(yetki)])
def karantina_goster(kimlik: str) -> dict:
    try:
        karantina.klasorde_goster(str(karantina.karantina_dosyasi(kimlik)))
    except (FileNotFoundError, ValueError) as e:
        raise HTTPException(status_code=409, detail=str(e))
    return {"ok": True}


@app.post("/api/karantina/{kimlik}/geri-yukle", dependencies=[Depends(yetki)])
def karantina_geri(kimlik: str) -> dict:
    try:
        return karantina.geri_yukle(kimlik)
    except (FileNotFoundError, FileExistsError, ValueError, OSError) as e:
        raise HTTPException(status_code=409, detail=str(e))


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
