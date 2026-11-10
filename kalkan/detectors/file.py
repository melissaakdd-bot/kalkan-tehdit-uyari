"""Dosya analizi: imza, hash, yapı ve içerik sinyalleri. Dosya asla çalıştırılmaz ya da diske açılmaz.

İsteğe bağlı motorlar: ClamAV (clamscan kuruluysa) ve VirusTotal hash sorgusu (API anahtarı varsa).
"""
from __future__ import annotations

import hashlib
import io
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile
from collections import Counter
from typing import Dict, List, Optional, Set

from .. import config
from ..models import Bulgu, Sonuc, sonuclandir

# EICAR antivirüs test dosyası: zararsızdır, tarayıcıların doğru çalıştığını sınamak için kullanılır.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

TEHLIKELI_UZANTILAR = {
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "ps1",
    "msi", "msp", "lnk", "dll", "cpl", "jar", "apk", "app", "dmg", "pkg", "sh", "iso", "img", "vhd",
    "reg", "chm", "inf", "scf", "one",
}
MAKROLU_UZANTILAR = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam"}
BELGE_UZANTILARI = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "csv", "rtf"}

# Sihirli baytlar -> tür
IMZALAR = [
    (b"MZ", "pe"),  # Windows çalıştırılabilir
    (b"\x7fELF", "elf"),
    (b"\xcf\xfa\xed\xfe", "macho"), (b"\xce\xfa\xed\xfe", "macho"), (b"\xca\xfe\xba\xbe", "macho"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),  # eski Office / MSI
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x89PNG", "png"), (b"\xff\xd8\xff", "jpg"), (b"GIF8", "gif"),
    (b"{\\rtf", "rtf"),
    (b"#!", "script"),
]
UZANTI_BEKLENEN = {
    "pdf": {"pdf"}, "png": {"png"}, "jpg": {"jpg"}, "jpeg": {"jpg"}, "gif": {"gif"},
    "docx": {"zip"}, "xlsx": {"zip"}, "pptx": {"zip"}, "doc": {"ole"}, "xls": {"ole"}, "ppt": {"ole"},
    "txt": {None}, "csv": {None}, "rtf": {"rtf"}, "zip": {"zip"},
}

SCRIPT_DESENLERI = [
    (rb"(?i)powershell(\.exe)?\s+.*-(e|enc|encodedcommand)\s", "Kodlanmış PowerShell komutu"),
    (rb"(?i)\b(iex|invoke-expression)\b", "PowerShell Invoke-Expression"),
    (rb"(?i)downloadstring|downloadfile|invoke-webrequest|net\.webclient", "İnternetten kod indirme"),
    (rb"(?i)frombase64string", "Base64 ile gizlenmiş yük"),
    (rb"(?i)wscript\.shell|shell\.application", "Windows Script Host ile komut çalıştırma"),
    (rb"(?i)certutil(\.exe)?\s+.*-(decode|urlcache)", "certutil ile indirme/çözme"),
    (rb"(?i)mshta(\.exe)?\s+(https?|javascript|vbscript):", "mshta ile uzaktan kod"),
    (rb"(?i)regsvr32\s+.*/i:https?", "regsvr32 ile uzaktan kod (Squiblydoo)"),
    (rb"(?i)(curl|wget)\s+[^\n|]*\|\s*(ba)?sh", "İnternetten indirip doğrudan kabukta çalıştırma"),
    (rb"(?i)eval\s*\(\s*(atob|unescape|string\.fromcharcode)", "Gizlenmiş JavaScript çalıştırma"),
    (rb"(?i)vssadmin(\.exe)?\s+delete\s+shadows", "Gölge kopyaları silme (fidye yazılımı davranışı)"),
    (rb"(?i)bcdedit\s+.*recoveryenabled\s+no", "Kurtarmayı kapatma (fidye yazılımı davranışı)"),
    (rb"(?i)autoopen|document_open|workbook_open|auto_open", "Belge açılınca otomatik çalışan makro"),
]


def _tur_bul(veri: bytes) -> Optional[str]:
    for imza, tur in IMZALAR:
        if veri.startswith(imza):
            return tur
    return None


def _entropi(veri: bytes) -> float:
    if not veri:
        return 0.0
    ornek = veri[: 2 * 1024 * 1024]
    sayac = Counter(ornek)
    n = len(ornek)
    return -sum(c / n * math.log2(c / n) for c in sayac.values())


def _uzantilar(ad: str) -> List[str]:
    parcalar = ad.lower().split(".")
    return parcalar[1:] if len(parcalar) > 1 else []


def _blok_listesi() -> Set[str]:
    try:
        return {s.strip().lower() for s in config.HASH_BLOCKLIST.read_text().splitlines() if s.strip() and not s.startswith("#")}
    except FileNotFoundError:
        return set()


def _clamav(veri: bytes) -> Optional[Bulgu]:
    if not shutil.which("clamscan"):
        return None
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(veri)
        yol = tmp.name
    try:
        p = subprocess.run(["clamscan", "--no-summary", yol], capture_output=True, text=True, timeout=120)
        if p.returncode == 1:
            imza = p.stdout.strip().split(":", 1)[-1].replace("FOUND", "").strip()
            return Bulgu("clamav", f"ClamAV imza eşleşmesi: {imza}", 95, "zararli", kritik=True)
    except (subprocess.TimeoutExpired, OSError):
        return None
    finally:
        os.unlink(yol)
    return None


def _virustotal(sha256: str) -> Optional[Dict[str, int]]:
    """Yalnızca hash gönderilir; dosyanın kendisi yüklenmez."""
    if not config.VIRUSTOTAL_API_KEY:
        return None
    istek = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
    )
    try:
        with urllib.request.urlopen(istek, timeout=15) as yanit:
            veri = json.load(yanit)
        return veri["data"]["attributes"]["last_analysis_stats"]
    except urllib.error.HTTPError as e:
        return {"bilinmiyor": 1} if e.code == 404 else None
    except (urllib.error.URLError, KeyError, ValueError, TimeoutError):
        return None


def _zip_incele(veri: bytes, bulgular: List[Bulgu]) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(veri))
        bilgiler = zf.infolist()
    except (zipfile.BadZipFile, RuntimeError, OSError):
        return
    adlar = [i.filename for i in bilgiler]
    if any(i.flag_bits & 0x1 for i in bilgiler):
        bulgular.append(Bulgu("sifreli_arsiv", "Şifreli arşiv: antivirüs taramasını atlatmak için sık kullanılır.", 35, "zararli"))
    if any(n.lower().endswith("vbaproject.bin") for n in adlar):
        bulgular.append(Bulgu("office_makro", "Office belgesi VBA makrosu içeriyor.", 45, "zararli"))
    icteki_tehlikeli = [n for n in adlar if (_uzantilar(os.path.basename(n)) or [""])[-1] in TEHLIKELI_UZANTILAR]
    if icteki_tehlikeli:
        bulgular.append(Bulgu(
            "arsivde_calistirilabilir",
            f"Arşivde çalıştırılabilir dosya var: {', '.join(icteki_tehlikeli[:3])}",
            55, "zararli",
        ))
    # Office ilişki dosyalarında uzak şablon (template injection)
    for n in adlar:
        if n.lower().endswith(".rels") and len(adlar) < 500:
            try:
                icerik = zf.read(n)[:200_000]
            except (RuntimeError, zipfile.BadZipFile, OSError):
                continue
            if re.search(rb'(?i)TargetMode="External"', icerik) and re.search(rb"(?i)attachedTemplate|oleObject", icerik):
                bulgular.append(Bulgu("uzak_sablon", "Belge açılırken internetten şablon/nesne çekiyor (template injection).", 50, "zararli"))
                break


def dosya_analiz(veri: bytes, ad: str, kaynak: str = "panel") -> Sonuc:
    sonuc = Sonuc("dosya", ad[:200], kaynak=kaynak)
    bulgular: List[Bulgu] = []

    sha256 = hashlib.sha256(veri).hexdigest()
    sonuc.ek.update({"sha256": sha256, "md5": hashlib.md5(veri).hexdigest(), "boyut": len(veri)})

    # 1) Bilinen kötü hash ve EICAR
    if sha256 in _blok_listesi():
        bulgular.append(Bulgu("bilinen_zararli", "Hash, yerel zararlı listesinde.", 100, "zararli", kritik=True))
    if EICAR in veri[:4096]:
        bulgular.append(Bulgu("eicar", "EICAR antivirüs test imzası bulundu (zararsız test dosyası, virüs gibi ele alınır).", 100, "zararli", kritik=True))

    # 2) Ad hileleri
    if "‮" in ad:
        bulgular.append(Bulgu("rtlo", "Dosya adında sağdan-sola karakteri var: gerçek uzantı gizleniyor.", 70, "zararli", kritik=True))
    uzantilar = _uzantilar(ad)
    son = uzantilar[-1] if uzantilar else ""
    if len(uzantilar) >= 2 and uzantilar[-2] in BELGE_UZANTILARI and son in TEHLIKELI_UZANTILAR:
        bulgular.append(Bulgu("cift_uzanti", f"Çift uzantı (.{uzantilar[-2]}.{son}): belge gibi görünen program.", 70, "zararli"))
    if re.search(r"\s{5,}\.", ad):
        bulgular.append(Bulgu("bosluk_hilesi", "Uzantı çok sayıda boşlukla gizlenmiş.", 50, "zararli"))
    if son in TEHLIKELI_UZANTILAR:
        bulgular.append(Bulgu("tehlikeli_uzanti", f".{son} çalıştırılabilir/kod içeren bir dosya türü.", 30, "zararli"))
    if son in MAKROLU_UZANTILAR:
        bulgular.append(Bulgu("makrolu_uzanti", f".{son} makro içerebilen Office biçimi.", 25, "zararli"))

    # 3) Gerçek tür ile uzantı uyumu
    tur = _tur_bul(veri)
    sonuc.ek["gercek_tur"] = tur or "bilinmiyor"
    if tur in ("pe", "elf", "macho"):
        if son in BELGE_UZANTILARI or son == "":
            bulgular.append(Bulgu("gizli_calistirilabilir", f"İçerik çalıştırılabilir program ({tur}) ama uzantı '.{son}'.", 80, "zararli", kritik=True))
        else:
            bulgular.append(Bulgu("calistirilabilir", f"Dosya çalıştırılabilir program ({tur}).", 25, "zararli"))
        ent = _entropi(veri)
        sonuc.ek["entropi"] = round(ent, 2)
        if ent > 7.2:
            bulgular.append(Bulgu("paketlenmis", f"Yüksek entropi ({ent:.2f}): sıkıştırılmış/şifrelenmiş (packed) program.", 25, "zararli"))
    elif son in UZANTI_BEKLENEN and tur not in UZANTI_BEKLENEN[son] and not (None in UZANTI_BEKLENEN[son] and tur in (None, "script")):
        bulgular.append(Bulgu("uzanti_uyumsuz", f"Uzantı '.{son}' ama içerik türü '{tur or 'bilinmiyor'}'.", 35, "zararli"))

    # 4) Biçime özel incelemeler
    if tur == "zip":
        _zip_incele(veri, bulgular)
    if tur == "ole":
        if re.search(rb"(?i)_VBA_PROJECT|VBA\x00|Macros", veri[:5_000_000]):
            bulgular.append(Bulgu("office_makro", "Eski biçim Office belgesi makro içeriyor.", 45, "zararli"))
    if tur == "pdf":
        bas = veri[:10_000_000]
        pdf_sinyaller = {
            rb"/JavaScript": ("pdf_js", "PDF içinde JavaScript var.", 35),
            rb"/JS\b": ("pdf_js", "PDF içinde JavaScript var.", 35),
            rb"/OpenAction": ("pdf_openaction", "PDF açılınca otomatik eylem çalıştırıyor.", 20),
            rb"/AA\b": ("pdf_openaction", "PDF otomatik eylem içeriyor.", 15),
            rb"/Launch": ("pdf_launch", "PDF dış program başlatmaya çalışıyor.", 50),
            rb"/EmbeddedFile": ("pdf_gomulu", "PDF içine gömülü dosya var.", 20),
        }
        gorulen: Set[str] = set()
        for desen, (kod, aciklama, agirlik) in pdf_sinyaller.items():
            if kod not in gorulen and re.search(desen, bas):
                gorulen.add(kod)
                bulgular.append(Bulgu(kod, aciklama, agirlik, "zararli"))

    # 5) Komut dizisi / davranış desenleri (ilk 5 MB)
    parca = veri[:5_000_000]
    for desen, aciklama in SCRIPT_DESENLERI:
        if re.search(desen, parca):
            bulgular.append(Bulgu("supheli_kod", f"Şüpheli kod deseni: {aciklama}.", 30, "zararli"))

    # 6) Harici motorlar
    clam = _clamav(veri)
    if clam:
        bulgular.append(clam)
    vt = _virustotal(sha256)
    if vt is not None:
        sonuc.ek["virustotal"] = vt
        kotu = int(vt.get("malicious", 0))
        if kotu >= 5:
            bulgular.append(Bulgu("virustotal", f"VirusTotal: {kotu} motor zararlı buldu.", 95, "zararli", kritik=True))
        elif kotu >= 1:
            bulgular.append(Bulgu("virustotal", f"VirusTotal: {kotu} motor zararlı buldu.", 45, "zararli"))

    sonuc.bulgular = bulgular
    return sonuclandir(sonuc)
