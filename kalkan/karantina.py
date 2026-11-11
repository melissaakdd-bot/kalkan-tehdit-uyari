"""Karantina: tehlikeli dosyayı silmeden, çalıştırılamaz biçimde ayrı bir klasöre taşır. Geri yüklenebilir.

Yalnızca kullanıcı panelden onayladığında ve yalnızca bir bilgisayar taramasının bulduğu dosyalar için
çalışır (API keyfi bir yol kabul etmez). Taşımadan önce dosyanın hash'i tarama anındakiyle karşılaştırılır;
dosya o arada değiştiyse taşınmaz.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config


def _dizin() -> Path:
    d = config.KARANTINA_DIR
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def _sha256(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def al(yol: str, beklenen_sha256: Optional[str], nedenler: List[str]) -> Dict[str, Any]:
    kaynak = Path(yol)
    if kaynak.is_symlink() or not kaynak.is_file():
        raise FileNotFoundError("Dosya bulunamadı ya da taşınmış")
    ozet = _sha256(kaynak)
    if beklenen_sha256 and ozet != beklenen_sha256:
        raise ValueError("Dosya taramadan sonra değişmiş; güvenlik için taşınmadı. Yeniden tarayın.")
    kimlik = uuid.uuid4().hex[:12]
    d = _dizin()
    hedef = d / f"{kimlik}.kalkan"
    eski_mod = stat.S_IMODE(kaynak.stat().st_mode)
    shutil.move(str(kaynak), str(hedef))
    os.chmod(hedef, 0o400)  # çalıştırma ve yazma izni kaldırılır
    meta = {"id": kimlik, "orijinal": str(kaynak), "ad": kaynak.name, "sha256": ozet, "zaman": time.time(),
            "boyut": hedef.stat().st_size, "mod": eski_mod, "nedenler": nedenler[:5]}
    (d / f"{kimlik}.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    return meta


def listele() -> List[Dict[str, Any]]:
    d = config.KARANTINA_DIR
    if not d.exists():
        return []
    ogeler = []
    for m in d.glob("*.json"):
        try:
            ogeler.append(json.loads(m.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return sorted(ogeler, key=lambda x: -x["zaman"])


def _karantina_yolu(kimlik: str) -> Path:
    if not kimlik.isalnum():
        raise ValueError("Geçersiz kimlik")
    return _dizin() / f"{kimlik}.kalkan"


def kalici_sil(kimlik: str) -> Dict[str, Any]:
    """Karantinadaki bir dosyayı geri dönüşü olmadan siler (yalnızca kullanıcı onayıyla çağrılır)."""
    dosya = _karantina_yolu(kimlik)
    meta_yol = dosya.with_suffix(".json")
    if not meta_yol.exists():
        raise FileNotFoundError("Karantinada böyle bir öğe yok")
    meta = json.loads(meta_yol.read_text(encoding="utf-8"))
    if dosya.exists():
        os.chmod(dosya, 0o600)
        dosya.unlink()
    meta_yol.unlink()
    return meta


def bosalt() -> int:
    sayi = 0
    for meta in listele():
        try:
            kalici_sil(meta["id"])
            sayi += 1
        except (OSError, ValueError):
            continue
    return sayi


def karantina_dosyasi(kimlik: str) -> Path:
    dosya = _karantina_yolu(kimlik)
    if not dosya.exists():
        raise FileNotFoundError("Karantinada böyle bir öğe yok")
    return dosya


def cop_kutusuna_tasi(yol: str, beklenen_sha256: Optional[str] = None) -> str:
    """Taramada bulunan bir dosyayı (hash'i değişmediyse) çöp kutusuna taşır."""
    kaynak = Path(yol)
    if kaynak.is_symlink() or not kaynak.is_file():
        raise FileNotFoundError("Dosya bulunamadı ya da taşınmış")
    if beklenen_sha256 and _sha256(kaynak) != beklenen_sha256:
        raise ValueError("Dosya taramadan sonra değişmiş; güvenlik için taşınmadı. Yeniden tarayın.")
    return cop_kutusuna(kaynak)


def cop_kutusuna(kaynak: Path) -> str:
    """Dosyayı ya da klasörü (ör. .app paketi) işletim sisteminin çöp kutusuna taşır; kullanıcı oradan geri alabilir.

    macOS'ta Finder üzerinden taşınır: "Geri Koy" çalışır ve yönetici izni gereken uygulamalarda Finder
    şifre sorar. Finder kullanılamazsa ~/.Trash'e taşınır.
    """
    if not (kaynak.exists() or kaynak.is_symlink()):
        raise FileNotFoundError("Bulunamadı ya da taşınmış")
    sistem = platform.system()
    if sistem == "Darwin":
        betik = 'on run argv\ntell application "Finder" to delete (POSIX file (item 1 of argv) as alias)\nend run'
        # Yönetici şifresi isteyen uygulamalarda kullanıcının yazmasına zaman tanınır
        p = subprocess.run(["osascript", "-e", betik, str(kaynak)], capture_output=True, text=True, timeout=180)
        if p.returncode == 0 and not kaynak.exists():
            return "Çöp Kutusu"
        cop = Path.home() / ".Trash"
    elif sistem == "Linux" and shutil.which("gio"):
        p = subprocess.run(["gio", "trash", str(kaynak)], capture_output=True, text=True, timeout=30)
        if p.returncode == 0:
            return "Çöp Kutusu"
        cop = Path.home() / ".local" / "share" / "Trash" / "files"
    else:
        raise OSError("Bu işletim sisteminde çöp kutusuna taşıma desteklenmiyor; karantinayı kullanın")
    cop.mkdir(parents=True, exist_ok=True)
    hedef = cop / kaynak.name
    if hedef.exists():
        hedef = cop / f"{kaynak.stem} {time.strftime('%H.%M.%S')}{kaynak.suffix}"
    shutil.move(str(kaynak), str(hedef))
    return str(cop)


def klasorde_goster(yol: str) -> None:
    """Dosyayı dosya yöneticisinde seçili olarak açar (Finder / Explorer / varsayılan dosya yöneticisi)."""
    p = Path(yol)
    if not p.exists():
        raise FileNotFoundError("Dosya artık bu konumda değil")
    sistem = platform.system()
    if sistem == "Darwin":
        komut = ["open", "-R", str(p)]
    elif sistem == "Windows":
        komut = ["explorer", f"/select,{p}"]
    else:
        komut = ["xdg-open", str(p.parent)]
    subprocess.run(komut, timeout=15, check=False)  # liste biçimi: kabuk yorumlamaz, yol enjeksiyon riski yok


def geri_yukle(kimlik: str) -> Dict[str, Any]:
    if not kimlik.isalnum():
        raise ValueError("Geçersiz kimlik")
    d = _dizin()
    meta_yol, dosya = d / f"{kimlik}.json", d / f"{kimlik}.kalkan"
    if not meta_yol.exists() or not dosya.exists():
        raise FileNotFoundError("Karantinada böyle bir öğe yok")
    meta = json.loads(meta_yol.read_text(encoding="utf-8"))
    hedef = Path(meta["orijinal"])
    if hedef.exists():
        raise FileExistsError("Orijinal konumda aynı adlı bir dosya var; önce onu taşıyın")
    hedef.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(dosya, 0o600)
    shutil.move(str(dosya), str(hedef))
    os.chmod(hedef, meta.get("mod", 0o600))
    meta_yol.unlink()
    return meta
