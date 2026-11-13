"""Kalkan.app oluşturucu (macOS, kişisel kullanım).

    python -m kalkan.kur_mac kur     # ~/Applications/Kalkan.app'i oluşturur, açılışta başlayan servisi kurar
    python -m kalkan.kur_mac durum   # servis ve uygulamanın durumu
    python -m kalkan.kur_mac kaldir  # servisi durdurur, uygulamayı Çöp Kutusu'na taşır (veriler kalır)

Uygulama bu bilgisayarda oluşturulduğu için Apple imzası gerekmez ve Gatekeeper uyarısı çıkmaz.
Uygulama proje klasörünü ve onun .venv'ini kullanır; proje klasörü taşınırsa "kur" yeniden çalıştırılmalıdır.
Hiçbir şey yönetici izni gerektirmez: her şey kullanıcının kendi klasörlerine kurulur.
"""
from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

from . import config
from .masaustu import SERVIS_ETIKETI

UYGULAMA_KIMLIGI = "com.yapayzekaokulum.kalkan"
SURUM = "0.5.0"


def varsayilan_yollar() -> dict:
    ev = Path.home()
    return {
        "app": ev / "Applications" / "Kalkan.app",
        "plist": ev / "Library" / "LaunchAgents" / f"{SERVIS_ETIKETI}.plist",
        "log": ev / "Library" / "Logs" / "Kalkan",
    }


def _betik(yol: Path, proje: Path, python: Path, modul: str) -> None:
    yol.write_text(
        "#!/bin/bash\n"
        "# Kalkan başlatıcısı (kalkan.kur_mac tarafından oluşturuldu)\n"
        'export KALKAN_UYGULAMA="$(cd "$(dirname "$0")/../.." && pwd)"\n'
        f'cd "{proje}" || exit 1\n'
        f'exec "{python}" -m {modul} "$@"\n',
        encoding="utf-8",
    )
    yol.chmod(0o755)


def _ikon(hedef: Path) -> bool:
    """Kalkan ikonunu .icns olarak üretir (sips/iconutil macOS ile gelir). Başarısızsa varsayılan ikon kalır."""
    if not shutil.which("iconutil"):
        return False
    import cv2
    import numpy as np

    S = 1024
    img = np.zeros((S, S, 4), np.uint8)
    # macOS ikon ızgarası: yuvarlak köşeli zemin + kalkan
    zemin = np.zeros((S, S), np.uint8)
    r, k = 180, 100
    cv2.rectangle(zemin, (k + r, k), (S - k - r, S - k), 255, -1)
    cv2.rectangle(zemin, (k, k + r), (S - k, S - k - r), 255, -1)
    for cx, cy in ((k + r, k + r), (S - k - r, k + r), (k + r, S - k - r), (S - k - r, S - k - r)):
        cv2.circle(zemin, (cx, cy), r, 255, -1, lineType=cv2.LINE_AA)
    img[zemin > 0] = (250, 246, 242, 255)
    kalkan = np.array([[512, 190], [790, 280], [775, 540], [700, 690], [512, 840], [324, 690], [249, 540], [234, 280]], np.int32)
    cv2.fillPoly(img, [kalkan], (221, 92, 44, 255), lineType=cv2.LINE_AA)
    cv2.polylines(img, [np.array([[385, 520], [480, 615], [655, 425]], np.int32)], False, (255, 255, 255, 255), 64, lineType=cv2.LINE_AA)
    with tempfile.TemporaryDirectory() as t:
        iconset = Path(t) / "Kalkan.iconset"
        iconset.mkdir()
        for boyut in (16, 32, 128, 256, 512):
            for kat, ek in ((1, ""), (2, "@2x")):
                px = boyut * kat
                cv2.imwrite(str(iconset / f"icon_{boyut}x{boyut}{ek}.png"),
                            cv2.resize(img, (px, px), interpolation=cv2.INTER_AREA))
        p = subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(hedef)], capture_output=True, text=True)
        return p.returncode == 0


def uygulama_olustur(app: Path, proje: Path, python: Path) -> None:
    """Kalkan.app paketini (yalnızca dosyaları) oluşturur. Var olan paket yeniden yazılır."""
    if app.exists():
        shutil.rmtree(app)
    macos, res = app / "Contents" / "MacOS", app / "Contents" / "Resources"
    macos.mkdir(parents=True)
    res.mkdir(parents=True)
    _betik(macos / "Kalkan", proje, python, "kalkan.masaustu")
    _betik(macos / "kalkan-sunucu", proje, python, "kalkan.sunucu")
    ikon_var = _ikon(res / "Kalkan.icns")
    info = {
        "CFBundleName": "Kalkan",
        "CFBundleDisplayName": "Kalkan",
        "CFBundleIdentifier": UYGULAMA_KIMLIGI,
        "CFBundleExecutable": "Kalkan",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": SURUM,
        "CFBundleVersion": SURUM,
        "LSMinimumSystemVersion": "11.0",
        "NSHighResolutionCapable": True,
        "LSApplicationCategoryType": "public.app-category.utilities",
        "NSHumanReadableCopyright": "Yapay Zekâ Okulum",
    }
    if ikon_var:
        info["CFBundleIconFile"] = "Kalkan"
    with open(app / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump(info, f)


def servis_plist_olustur(plist: Path, app: Path, proje: Path, log: Path) -> None:
    log.mkdir(parents=True, exist_ok=True)
    plist.parent.mkdir(parents=True, exist_ok=True)
    veri = {
        "Label": SERVIS_ETIKETI,
        "ProgramArguments": [str(app / "Contents" / "MacOS" / "kalkan-sunucu")],
        "WorkingDirectory": str(proje),
        "RunAtLoad": True,  # oturum açılınca başla
        "KeepAlive": {"SuccessfulExit": False},  # çökerse yeniden başlat, düzgün kapanırsa bırak
        "ThrottleInterval": 30,
        "ProcessType": "Background",
        "StandardOutPath": str(log / "sunucu.log"),
        "StandardErrorPath": str(log / "sunucu.log"),
    }
    with open(plist, "wb") as f:
        plistlib.dump(veri, f)


def _launchctl(*arg: str) -> subprocess.CompletedProcess:
    return subprocess.run(["launchctl", *arg], capture_output=True, text=True, timeout=20)


def servis_yukle(plist: Path) -> None:
    import time

    alan = f"gui/{os.getuid()}"
    # Eski sürüm yüklüyse kaldır. bootout eşzamansızdır: servis tamamen kapanmadan bootstrap
    # "5: Input/output error" verir, bu yüzden kapanması beklenir.
    _launchctl("bootout", f"{alan}/{SERVIS_ETIKETI}")
    for _ in range(40):
        if _launchctl("print", f"{alan}/{SERVIS_ETIKETI}").returncode != 0:
            break
        time.sleep(0.25)
    for deneme in range(5):
        p = _launchctl("bootstrap", alan, str(plist))
        if p.returncode == 0:
            return
        time.sleep(1 + deneme)
    raise RuntimeError(f"Servis yüklenemedi: {p.stderr.strip()}")


def kur(yollar: Optional[dict] = None, servis: bool = True) -> dict:
    yollar = yollar or varsayilan_yollar()
    proje = config.BASE_DIR
    python = proje / ".venv" / "bin" / "python"
    if not python.exists():
        python = Path(sys.executable)
    try:
        import webview  # noqa: F401
    except ImportError:
        raise RuntimeError("pywebview kurulu değil: .venv/bin/pip install -r requirements.txt")
    yollar["app"].parent.mkdir(parents=True, exist_ok=True)
    uygulama_olustur(yollar["app"], proje, python)
    servis_plist_olustur(yollar["plist"], yollar["app"], proje, yollar["log"])
    if servis:
        servis_yukle(yollar["plist"])
    return {k: str(v) for k, v in yollar.items()}


def kaldir() -> None:
    from .karantina import cop_kutusuna

    y = varsayilan_yollar()
    _launchctl("bootout", f"gui/{os.getuid()}/{SERVIS_ETIKETI}")
    if y["plist"].exists():
        y["plist"].unlink()
    if y["app"].exists():
        cop_kutusuna(y["app"])
    print("Kalkan servisi durduruldu, Kalkan.app Çöp Kutusu'na taşındı. Tarama geçmişi ve karantina korunuyor.")


def durum() -> None:
    from .masaustu import sunucu_hazir

    y = varsayilan_yollar()
    p = _launchctl("print", f"gui/{os.getuid()}/{SERVIS_ETIKETI}")
    print(f"Uygulama:  {'var' if y['app'].exists() else 'yok'}  ({y['app']})")
    print(f"Servis:    {'yüklü' if p.returncode == 0 else 'yüklü değil'}")
    # Sunucu açılışta modelleri yüklerken ~10 sn yanıt vermez; servis yeni başladıysa bekle
    print(f"Sunucu:    {'çalışıyor' if sunucu_hazir(bekle=20 if p.returncode == 0 else 0) else 'yanıt vermiyor'}"
          f"  (http://127.0.0.1:{config.PORT})")
    print(f"Kayıtlar:  {y['log'] / 'sunucu.log'}")


def main() -> None:
    komut = sys.argv[1] if len(sys.argv) > 1 else "kur"
    if komut == "kur":
        sonuc = kur()
        print(f"Kalkan.app hazır: {sonuc['app']}")
        print("Açılışta başlayan servis kuruldu. Uygulamayı Finder > Uygulamalar'dan ya da Spotlight'tan (⌘ boşluk, 'Kalkan') açabilirsiniz.")
    elif komut == "kaldir":
        kaldir()
    elif komut == "durum":
        durum()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
