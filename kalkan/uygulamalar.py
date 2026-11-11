"""macOS uygulama yöneticisi: yüklü uygulamaları listeler, güvenliğini değerlendirir ve artıklarıyla kaldırır.

macOS'ta bir uygulamayı Çöp Kutusu'na sürüklemek yalnızca .app paketini siler; ayarlar, önbellekler,
kapsayıcılar ve açılışta başlayan servisler ~/Library altında kalır. Bu modül bunları bulur.

Güvenlik kuralları:
- Apple'ın sistem uygulamaları (com.apple.*) listelenmez ve kaldırılamaz.
- Hiçbir şey kalıcı silinmez: uygulama ve artıklar Finder üzerinden Çöp Kutusu'na taşınır ("Geri Koy" çalışır).
- Kaldırılabilecek yollar yalnızca sunucunun kendi bulduğu listeden seçilir; API keyfi bir yol kabul etmez.
- Açık olan uygulama kaldırılmaz (önce kapatılmalı).
- Ad eşleşmesiyle bulunan klasör (ör. "Application Support/Google") başka bir yüklü uygulamayla
  paylaşılıyorsa önerilmez; yalnızca paket kimliğiyle (bundle id) kesin eşleşenler varsayılan seçilir.
"""
from __future__ import annotations

import hashlib
import os
import platform
import plistlib
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config

_onbellek: Dict[str, Dict[str, Any]] = {}  # yol -> ayrıntılar (değişiklik zamanıyla birlikte)
_kilit = threading.Lock()
_calisan: Optional[threading.Thread] = None

# Paket kimliğiyle aranacak Library konumları: (alt klasör, ad kalıbı)
BID_KONUMLARI = [
    ("Application Support", "{bid}"), ("Caches", "{bid}"), ("Preferences", "{bid}.plist"),
    ("Containers", "{bid}"), ("Saved Application State", "{bid}.savedState"), ("HTTPStorages", "{bid}"),
    ("HTTPStorages", "{bid}.binarycookies"), ("WebKit", "{bid}"), ("Cookies", "{bid}.binarycookies"),
    ("Logs", "{bid}"), ("Application Scripts", "{bid}"),
]
# Ad ile aranacak konumlar (yalnızca başka uygulamayla paylaşılmıyorsa önerilir)
AD_KONUMLARI = ["Application Support", "Caches", "Logs"]


def destekleniyor() -> bool:
    return platform.system() == "Darwin" or bool(os.getenv("KALKAN_UYGULAMA_TEST"))


def _kokler() -> List[Path]:
    return [Path(p).expanduser() for p in config.UYGULAMA_DIZINLERI]


def _library() -> Path:
    return Path(config.KULLANICI_LIBRARY).expanduser()


def _kimlik(yol: Path) -> str:
    return hashlib.sha1(str(yol).encode()).hexdigest()[:12]


def _info(app: Path) -> Dict[str, Any]:
    try:
        with open(app / "Contents" / "Info.plist", "rb") as f:
            return plistlib.load(f)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}


def _komut(arg: List[str], zaman: int = 20) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(arg, capture_output=True, text=True, timeout=zaman)
    except (subprocess.TimeoutExpired, OSError) as e:
        return subprocess.CompletedProcess(arg, 1, "", str(e))


def _boyut(yol: Path) -> Optional[int]:
    p = _komut(["du", "-sk", str(yol)], 60)
    try:
        return int(p.stdout.split()[0]) * 1024
    except (IndexError, ValueError):
        return None


def _imza(app: Path) -> Dict[str, Any]:
    e = _komut(["codesign", "-dv", "--verbose=2", str(app)]).stderr
    if "not signed" in e:
        return {"durum": "imzasiz", "aciklama": "İmzasız: geliştiricisi doğrulanamıyor"}
    if "Signature=adhoc" in e:
        return {"durum": "adhoc", "aciklama": "Geçici (ad-hoc) imza: geliştiricisi doğrulanamıyor"}
    if "Apple Mac OS Application Signing" in e:
        return {"durum": "appstore", "aciklama": "App Store"}
    m = re.search(r"Authority=Developer ID Application: (.+)", e)
    if m:
        return {"durum": "gelistirici", "aciklama": f"Doğrulanmış geliştirici: {m.group(1).strip()}"}
    if "Software Signing" in e:
        return {"durum": "apple", "aciklama": "Apple"}
    return {"durum": "bilinmiyor", "aciklama": "İmza okunamadı"}


def _gatekeeper(app: Path) -> Dict[str, Any]:
    e = _komut(["spctl", "-a", "-vv", "-t", "exec", str(app)], 30).stderr
    if "accepted" in e:
        kaynak = re.search(r"source=(.+)", e)
        return {"durum": "kabul", "aciklama": (kaynak.group(1).strip() if kaynak else "Onaylı")}
    if "rejected" in e:
        return {"durum": "red", "aciklama": "Gatekeeper onaylamıyor (Apple'ın noter onayından geçmemiş)"}
    return {"durum": "bilinmiyor", "aciklama": ""}


def _mdls(app: Path, ad: str) -> Optional[str]:
    p = _komut(["mdls", "-raw", "-name", ad, str(app)], 10)
    v = p.stdout.strip()
    return None if not v or v == "(null)" else v


def _calisiyor_mu(app: Path) -> bool:
    p = _komut(["pgrep", "-f", str(app / "Contents" / "MacOS")], 5)
    return p.returncode == 0 and bool(p.stdout.strip())


def _temel(app: Path) -> Optional[Dict[str, Any]]:
    info = _info(app)
    bid = str(info.get("CFBundleIdentifier") or "")
    if not bid or bid.startswith("com.apple."):
        return None  # sistem uygulamaları korunur
    return {
        "id": _kimlik(app),
        "yol": str(app),
        "ad": str(info.get("CFBundleDisplayName") or info.get("CFBundleName") or app.stem),
        "dosya_adi": app.stem,
        "bundle_id": bid,
        "surum": str(info.get("CFBundleShortVersionString") or ""),
    }


def _ayrinti_hesapla(app: Path) -> Dict[str, Any]:
    d: Dict[str, Any] = {"mtime": app.stat().st_mtime}
    d["boyut"] = _boyut(app)
    d["imza"] = _imza(app)
    son = _mdls(app, "kMDItemLastUsedDate")
    d["son_kullanim"] = son[:10] if son else None
    nereden = _mdls(app, "kMDItemWhereFroms")
    adresler = re.findall(r'"([^"]+)"', nereden or "")
    d["nereden"] = adresler[0] if adresler else None
    d["gatekeeper"] = _gatekeeper(app)
    d["risk"] = _risk(d)
    return d


def _risk(d: Dict[str, Any]) -> List[str]:
    nedenler: List[str] = []
    if d["imza"]["durum"] in ("imzasiz", "adhoc"):
        nedenler.append(d["imza"]["aciklama"])
    if d["gatekeeper"]["durum"] == "red":
        nedenler.append(d["gatekeeper"]["aciklama"])
    if d.get("nereden"):
        from .detectors.url import url_analiz
        u = url_analiz(d["nereden"], kaynak="sistem")
        if u.seviye != "guvenli":
            nedenler.append(f"Riskli bir adresten indirilmiş: {u.ek.get('host', '')} (puan {u.puan})")
    return nedenler


def _arkaplan(uygulamalar: List[Path]) -> None:
    def tek(app: Path) -> None:
        try:
            d = _ayrinti_hesapla(app)
        except OSError:
            return
        with _kilit:
            _onbellek[str(app)] = d

    with ThreadPoolExecutor(max_workers=4) as havuz:
        list(havuz.map(tek, uygulamalar))


def _bulunanlar() -> List[Path]:
    sonuc: List[Path] = []
    for kok in _kokler():
        if kok.is_dir():
            sonuc += sorted(p for p in kok.glob("*.app") if p.is_dir() and not p.is_symlink())
    return sonuc


def listele() -> Dict[str, Any]:
    global _calisan
    uygulamalar = _bulunanlar()
    eksik = []
    liste = []
    for app in uygulamalar:
        t = _temel(app)
        if not t:
            continue
        with _kilit:
            d = _onbellek.get(str(app))
        try:
            guncel = d is not None and d["mtime"] == app.stat().st_mtime
        except OSError:
            continue
        if guncel:
            t.update({k: v for k, v in d.items() if k != "mtime"})
        else:
            eksik.append(app)
        liste.append(t)
    with _kilit:
        if eksik and (_calisan is None or not _calisan.is_alive()):
            _calisan = threading.Thread(target=_arkaplan, args=(eksik,), name="uygulama-ayrinti", daemon=True)
            _calisan.start()
    return {"uygulamalar": liste, "hazir": not eksik}


def _bul(kimlik: str) -> Path:
    for app in _bulunanlar():
        if _kimlik(app) == kimlik:
            return app
    raise FileNotFoundError("Uygulama bulunamadı")


def artiklar(kimlik: str) -> Dict[str, Any]:
    """Uygulamanın Library'de bıraktığı dosyaları bulur. Varsayılan seçim yalnızca kesin eşleşmelerdir."""
    app = _bul(kimlik)
    t = _temel(app)
    if not t:
        raise PermissionError("Sistem uygulamaları kaldırılamaz")
    bid, lib = t["bundle_id"], _library()
    adaylar: List[Dict[str, Any]] = []
    gorulen = set()

    def ekle(yol: Path, eslesme: str, secili: bool) -> None:
        if str(yol) in gorulen or not (yol.exists() or yol.is_symlink()):
            return
        gorulen.add(str(yol))
        adaylar.append({"yol": str(yol), "eslesme": eslesme, "secili": secili,
                        "boyut": _boyut(yol) if yol.is_dir() else (yol.lstat().st_size if yol.exists() else 0)})

    for alt, kalip in BID_KONUMLARI:
        ekle(lib / alt / kalip.format(bid=bid), "paket kimliği", True)
    # Açılışta başlayan servisler ve ByHost tercihleri: adı paket kimliğiyle başlayanlar
    for alt, desen in (("LaunchAgents", f"{bid}*.plist"), ("Preferences/ByHost", f"{bid}.*.plist")):
        for p in (lib / alt).glob(desen) if (lib / alt).is_dir() else []:
            ekle(p, "paket kimliği", True)
    # Grup kapsayıcıları: TAKIM.paketkimligi biçimi
    gk = lib / "Group Containers"
    if gk.is_dir():
        for p in gk.iterdir():
            if p.name.endswith("." + bid) or p.name == bid:
                ekle(p, "paket kimliği", True)
    # Ad eşleşmesi: başka bir yüklü uygulama aynı adı taşıyorsa önerilmez
    diger_adlar = {(_temel(a) or {}).get("ad", "").lower() for a in _bulunanlar() if a != app}
    diger_adlar |= {a.stem.lower() for a in _bulunanlar() if a != app}
    for ad in {t["ad"], t["dosya_adi"]}:
        # "/" ya da ".." içeren bir ad Library dışına çıkan bir yol üretebilirdi
        if not ad or "/" in ad or ad.strip(".") == "" or ad.lower() in diger_adlar or len(ad) < 3:
            continue
        for alt in AD_KONUMLARI:
            ekle(lib / alt / ad, "uygulama adı", True)

    return {
        "uygulama": {**t, "boyut": _boyut(app), "calisiyor": _calisiyor_mu(app)},
        "artiklar": adaylar,
    }


def kaldir(kimlik: str, secilen_artiklar: List[str]) -> Dict[str, Any]:
    from .karantina import cop_kutusuna

    bilgi = artiklar(kimlik)
    app = Path(bilgi["uygulama"]["yol"])
    if bilgi["uygulama"]["calisiyor"]:
        raise RuntimeError(f"{bilgi['uygulama']['ad']} şu an açık. Önce uygulamadan çıkın (⌘Q), sonra tekrar deneyin.")
    izinli = {a["yol"] for a in bilgi["artiklar"]}
    gecersiz = [y for y in secilen_artiklar if y not in izinli]
    if gecersiz:
        raise PermissionError("Listede olmayan bir yol seçildi; güvenlik için işlem yapılmadı")
    sonuc: Dict[str, Any] = {"uygulama": None, "artiklar": [], "hatalar": []}
    try:
        cop_kutusuna(app)
        sonuc["uygulama"] = str(app)
    except (OSError, PermissionError, subprocess.TimeoutExpired) as e:
        # Uygulama kaldırılamadıysa artıklarına da dokunulmaz
        raise PermissionError(f"Uygulama Çöp Kutusu'na taşınamadı: {e}")
    for y in secilen_artiklar:
        try:
            cop_kutusuna(Path(y))
            sonuc["artiklar"].append(y)
        except (OSError, subprocess.TimeoutExpired) as e:
            sonuc["hatalar"].append({"yol": y, "hata": str(e)})
    with _kilit:
        _onbellek.pop(str(app), None)
    return sonuc
