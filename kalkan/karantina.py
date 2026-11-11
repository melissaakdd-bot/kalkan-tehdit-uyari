"""Karantina: tehlikeli dosyayı silmeden, çalıştırılamaz biçimde ayrı bir klasöre taşır. Geri yüklenebilir.

Yalnızca kullanıcı panelden onayladığında ve yalnızca bir bilgisayar taramasının bulduğu dosyalar için
çalışır (API keyfi bir yol kabul etmez). Taşımadan önce dosyanın hash'i tarama anındakiyle karşılaştırılır;
dosya o arada değiştiyse taşınmaz.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
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
