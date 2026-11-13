"""Ortam değişkenlerinden okunan ayarlar. Gizli değerler koda yazılmaz."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_yukle(yol: Path) -> None:
    """Basit .env okuyucu. Zaten tanımlı ortam değişkenlerinin üzerine yazmaz."""
    if not yol.is_file():
        return
    for satir in yol.read_text(encoding="utf-8").splitlines():
        satir = satir.strip()
        if not satir or satir.startswith("#") or "=" not in satir:
            continue
        ad, deger = satir.split("=", 1)
        ad = ad.strip().removeprefix("export ").strip()
        deger = deger.strip().strip('"').strip("'")
        if ad and deger and ad not in os.environ:
            os.environ[ad] = deger


_env_yukle(BASE_DIR / ".env")
DATA_DIR = Path(os.getenv("KALKAN_DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "kalkan.db"
MODEL_PATH = DATA_DIR / "metin_modeli.joblib"
HASH_BLOCKLIST = DATA_DIR / "zararli_hashler.txt"


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "evet", "yes", "on"}


# Panel erişimi: tanımlıysa her istek X-Kalkan-Token başlığı (SSE için ?token=) ister.
PANEL_TOKEN = os.getenv("KALKAN_TOKEN", "")

# Uyarı eşikleri (0-100 risk puanı)
SUPHELI_ESIK = int(os.getenv("KALKAN_SUPHELI_ESIK", "30"))
TEHLIKELI_ESIK = int(os.getenv("KALKAN_TEHLIKELI_ESIK", "60"))

# Metin modeli bu tehdit olasılığının üstünde bulgu ekler (testte %80 eşiğinde TR e-postada yanlış alarm %2,8)
METIN_ML_ESIK = float(os.getenv("KALKAN_METIN_ML_ESIK", "0.8"))
# URL modeli bu olasılığın üstünde açıklamalı bir bulgu ekler (testte %90 eşiğinde yanlış alarm %0,3)
URL_ML_ESIK = float(os.getenv("KALKAN_URL_ML_ESIK", "0.9"))

# Dosya yükleme sınırı
MAX_DOSYA_MB = int(os.getenv("KALKAN_MAX_DOSYA_MB", "25"))
MAX_TOPLU_MB = int(os.getenv("KALKAN_MAX_TOPLU_MB", "200"))

# LLM katmanı varsayılan olarak kapalı: içerik dış servise gider, KVKK değerlendirmesi gerekir.
LLM_ENABLED = _bool("KALKAN_LLM", False)
LLM_MODEL = os.getenv("KALKAN_LLM_MODEL", "claude-opus-5-5")
LLM_MAX_CHARS = int(os.getenv("KALKAN_LLM_MAX_CHARS", "40000"))

# İsteğe bağlı dış servisler
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ALERT_WEBHOOK_URL = os.getenv("KALKAN_WEBHOOK_URL", "")  # Slack/Teams uyumlu {"text": ...}

# Tarayıcı eklentisinin indirdiği dosyalar yalnızca bu klasörden okunabilir
INDIRME_DIZINI = os.getenv("KALKAN_INDIRME_DIZINI", str(Path.home() / "Downloads"))

# Masaüstü uygulamasının (Kalkan.app) kullandığı sabit yerel port
PORT = int(os.getenv("KALKAN_PORT", "8790"))

# Otomatik bilgisayar taraması (hızlı tarama) aralığı, saat. 0 kapatır.
OTOMATIK_TARAMA_SAAT = float(os.getenv("KALKAN_OTOMATIK_TARAMA_SAAT", "24"))
# Karantinaya alınan dosyaların taşındığı klasör
KARANTINA_DIR = Path(os.getenv("KALKAN_KARANTINA_DIR", str(Path.home() / ".kalkan" / "karantina")))

# Uygulama yöneticisi (macOS): taranan uygulama klasörleri ve artıkların aranacağı Library
UYGULAMA_DIZINLERI = [p for p in os.getenv("KALKAN_UYGULAMA_DIZINLERI", "/Applications:~/Applications").split(":") if p]
KULLANICI_LIBRARY = os.getenv("KALKAN_KULLANICI_LIBRARY", str(Path.home() / "Library"))

# İzleyiciler
WATCH_DIR = os.getenv("KALKAN_WATCH_DIR", "")
WATCH_INTERVAL = int(os.getenv("KALKAN_WATCH_INTERVAL", "5"))

IMAP_HOST = os.getenv("KALKAN_IMAP_HOST", "")
IMAP_USER = os.getenv("KALKAN_IMAP_USER", "")
IMAP_PASSWORD = os.getenv("KALKAN_IMAP_PASSWORD", "")
IMAP_FOLDER = os.getenv("KALKAN_IMAP_FOLDER", "INBOX")
IMAP_INTERVAL = int(os.getenv("KALKAN_IMAP_INTERVAL", "60"))
