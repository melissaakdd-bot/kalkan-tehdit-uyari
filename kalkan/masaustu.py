"""Kalkan masaüstü penceresi: paneli tarayıcı yerine kendi penceresinde açar.

Arka plan servisi çalışmıyorsa önce onu başlatmayı dener (launchctl); servis kurulu değilse sunucuyu
bu pencerenin içinde başlatır (bu durumda pencere kapanınca koruma da durur).
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
import urllib.request

from . import config

SERVIS_ETIKETI = "com.yapayzekaokulum.kalkan.sunucu"
ADRES = f"http://127.0.0.1:{config.PORT}"


def sunucu_hazir(bekle: float = 0) -> bool:
    son = time.time() + bekle
    while True:
        try:
            with urllib.request.urlopen(ADRES + "/api/durum", timeout=1.5) as y:
                if y.status == 200:
                    return True
        except OSError:
            pass
        if time.time() >= son:
            return False
        time.sleep(0.4)


def _servisi_baslat() -> bool:
    """Kurulu LaunchAgent'ı uyandırır. Kurulu değilse False döner."""
    p = subprocess.run(["launchctl", "kickstart", f"gui/{os.getuid()}/{SERVIS_ETIKETI}"],
                       capture_output=True, text=True, timeout=10)
    return p.returncode == 0


def _icerde_baslat() -> None:
    from .sunucu import main as sunucu_main

    threading.Thread(target=sunucu_main, name="kalkan-sunucu", daemon=True).start()


HATA_SAYFASI = """<!doctype html><html lang="tr"><meta charset="utf-8">
<body style="font:15px -apple-system,sans-serif;padding:40px;color:#16181d">
<h2>🛡️ Kalkan başlatılamadı</h2>
<p>Yerel sunucu {adres} adresinde yanıt vermiyor.</p>
<p>Kayıtlar: <code>~/Library/Logs/Kalkan/sunucu.log</code></p>
<p>Sorun sürerse proje klasöründe şu komutla yeniden kurun:<br>
<code>.venv/bin/python -m kalkan.kur_mac kur</code></p></body></html>"""


def _kimlik_ayarla() -> None:
    """Uygulama içeride Python'u çalıştırdığı için Dock ve menü çubuğu "Python" gösterirdi; Kalkan yapılır."""
    try:
        from AppKit import NSApplication, NSImage
        from Foundation import NSBundle
    except ImportError:
        return
    paket = NSBundle.mainBundle()
    for sozluk in (paket.localizedInfoDictionary(), paket.infoDictionary()):
        if sozluk is not None:
            sozluk["CFBundleName"] = "Kalkan"
    uygulama = os.environ.get("KALKAN_UYGULAMA")
    if uygulama:
        ikon = os.path.join(uygulama, "Contents", "Resources", "Kalkan.icns")
        if os.path.exists(ikon):
            NSApplication.sharedApplication().setApplicationIconImage_(NSImage.alloc().initWithContentsOfFile_(ikon))


def main() -> None:
    import webview

    _kimlik_ayarla()

    # Rapor ve toplu tarama CSV'leri pencereden indirilebilsin (İndirilenler klasörüne kaydedilir)
    webview.settings["ALLOW_DOWNLOADS"] = True
    if not sunucu_hazir():
        if not (_servisi_baslat() and sunucu_hazir(bekle=20)):
            _icerde_baslat()
            sunucu_hazir(bekle=20)
    if sunucu_hazir():
        webview.create_window("Kalkan", ADRES, width=1280, height=860, min_size=(420, 560))
    else:
        webview.create_window("Kalkan", html=HATA_SAYFASI.format(adres=ADRES), width=640, height=360)
    webview.start()


if __name__ == "__main__":
    main()
