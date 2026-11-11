"""Bilgisayar taraması: diskteki dosyaları ve açılışta otomatik başlayan programları denetler.

Salt okunurdur: hiçbir dosyayı değiştirmez, silmez ya da çalıştırmaz. Tehlikeli bulunan dosyalar
yalnızca kullanıcı panelden onaylarsa karantinaya taşınır (kalkan/karantina.py).

Akıllı tarama: her dosya önce adı ve ilk baytlarıyla elenir. Yalnızca program, betik, arşiv, Office/PDF
ya da türü uzantısıyla uyuşmayan dosyalar derin analize girer. Fotoğraf, video gibi dosyaların
uzantısı içeriğiyle uyuşuyorsa okunmaz.

Komut satırından:  python -m kalkan.sistem_tarama hizli|tam|<klasör>
"""
from __future__ import annotations

import os
import platform
import plistlib
import re
import stat
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import config
from .detectors.file import BELGE_UZANTILARI, IMZALAR, MAKROLU_UZANTILAR, TEHLIKELI_UZANTILAR, dosya_analiz
from .models import Bulgu, Sonuc, sonuclandir

EV = Path.home()

DERIN_UZANTILAR = TEHLIKELI_UZANTILAR | MAKROLU_UZANTILAR | {
    "pdf", "doc", "xls", "ppt", "docx", "xlsx", "pptx", "rtf", "zip", "rar", "7z", "command", "bat", "cmd", "vbs",
    "hta", "ps1", "scpt", "workflow",
}
# Taranmayan klasörler: bağımlılık/önbellek klasörleri (çok büyük, kullanıcı dosyası değil) ve sistem verisi
ATLA_ADLAR = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".cache", ".npm", ".cargo", ".rustup", ".gradle",
    ".m2", ".pyenv", ".nvm", ".Trash", "Caches", "Containers", "Group Containers", "Photos Library.photoslibrary",
    "Music", "Movies", "CloudStorage", "Mobile Documents", "Metadata", "site-packages", "DerivedData", "veri_setleri",
}
SF_DATALESS = 0x40000000  # macOS: içeriği bulutta olan dosya (sys/stat.h)
BASLANGIC_ADLARI = {"LaunchAgents", "LaunchDaemons", "autostart", "Startup"}
AZAMI_DOSYA = 500_000

_isler: Dict[str, Dict[str, Any]] = {}
_kilit = threading.Lock()


# ---------------------------------------------------------------------------
# Hangi konumlar taranır
# ---------------------------------------------------------------------------
def hizli_konumlar() -> List[Tuple[Path, int]]:
    """(klasör, en fazla derinlik). Saldırganın dosya bırakması en olası yerler."""
    adaylar = [
        (EV / "Downloads", 6), (EV / "Desktop", 4), (EV / "Documents", 4),
        (Path("/tmp"), 3), (Path("/Users/Shared"), 4),
        (EV / "Library" / "LaunchAgents", 1), (Path("/Library/LaunchAgents"), 1), (Path("/Library/LaunchDaemons"), 1),
        (EV / ".config" / "autostart", 1),
    ]
    if platform.system() == "Windows":
        appdata = Path(os.environ.get("APPDATA", EV / "AppData" / "Roaming"))
        adaylar.append((appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup", 2))
    return [(k, d) for k, d in adaylar if k.exists()]


def _dosyalar(kok: Path, derinlik: int, is_: Dict[str, Any]) -> Iterator[Path]:
    kok_derinlik = len(kok.parts)
    for dizin, altlar, dosyalar in os.walk(kok, topdown=True, onerror=lambda e: _erisim_hatasi(is_, e)):
        d = Path(dizin)
        if len(d.parts) - kok_derinlik >= derinlik:
            altlar[:] = []
        # .app paketlerinin içine girme: imzalı uygulama dosyaları binlercedir ve tek tek anlamsızdır
        # Başlangıç klasörleri ayrıca kendi kurallarıyla taranır (BASLANGIC_ADLARI), burada tekrar girilmez
        altlar[:] = [a for a in altlar if a not in ATLA_ADLAR and a not in BASLANGIC_ADLARI
                     and not a.endswith((".app", ".photoslibrary", ".framework"))]
        is_["konum"] = str(d)
        for ad in dosyalar:
            yield d / ad


def _erisim_hatasi(is_: Dict[str, Any], hata: OSError) -> None:
    is_["erisilemeyen"] += 1


def _ilk_baytlar(yol: Path) -> bytes:
    with open(yol, "rb") as f:
        return f.read(16)


BETIK_UZANTILARI = {"js", "jse", "mjs", "cjs", "vbs", "vbe", "ps1", "sh", "command", "bat", "cmd", "hta", "wsf", "wsh", "scpt", "py"}


def _uygulama_verisi_mi(yol: Path) -> bool:
    try:
        goreli = yol.relative_to(EV)
    except ValueError:
        return False
    ilk = goreli.parts[0] if goreli.parts else ""
    return ilk == "Library" or ilk.startswith(".")


def _derin_mi(yol: Path) -> bool:
    """Ucuz ön eleme: ad ve ilk 16 bayt."""
    ad = yol.name.lower()
    if ad.startswith("~$") or ad == ".ds_store":  # Office'in açık belge kilit dosyaları ve Finder dosyası
        return False
    if "‮" in yol.name or re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.[a-z0-9]{2,4}$", ad):
        return True
    son = ad.rsplit(".", 1)[-1] if "." in ad else ""
    # Uygulama veri klasörlerinde (~/Library, ~/.vscode gibi gizli klasörler) binlerce meşru betik ve önbellek
    # dosyası bulunur; bunlar derin incelenmez. Programlar, arşivler ve tür gizlemeleri yine incelenir;
    # açılışta başlayan öğeler ayrıca kendi kurallarıyla denetlenir.
    if son in BETIK_UZANTILARI and _uygulama_verisi_mi(yol):
        return False
    if son in DERIN_UZANTILAR:
        return True
    try:
        bas = _ilk_baytlar(yol)
    except OSError:
        return False
    tur = next((t for imza, t in IMZALAR if bas.startswith(imza)), None)
    # Belge/görsel uzantılı ama program içeriği: en tipik gizleme
    if tur in ("pe", "elf", "macho") and son in BELGE_UZANTILARI:
        return True
    # Uzantısız Windows programı (macOS/Linux'ta olağan değil)
    return tur == "pe" and son == ""


# ---------------------------------------------------------------------------
# Açılışta başlayan programlar (kalıcılık / persistence)
# ---------------------------------------------------------------------------
_TEHLIKELI_KOMUT = [
    (r"(curl|wget)\b[^|;]*\|\s*(ba|z)?sh", "İnternetten indirdiğini doğrudan kabukta çalıştırıyor"),
    (r"base64\s+(-d|--decode|-D)", "Base64 ile gizlenmiş komut çözüyor"),
    (r"osascript\s+-e", "AppleScript komutu çalıştırıyor"),
    (r"python[0-9.]*\s+-c", "Satır içi Python kodu çalıştırıyor"),
    (r"(ba|z)?sh\s+-c\s+.*https?://", "Kabukta internet adresi içeren komut çalıştırıyor"),
    (r"\bnc\b.*-e\s", "Netcat ile uzak kabuk açıyor"),
]


def _gizli_konum(yol: str) -> Optional[str]:
    if re.match(r"^(/private)?/tmp/|^/var/tmp/|^/Users/Shared/", yol):
        return "geçici ya da paylaşılan bir klasörden"
    if str(EV / "Downloads") in yol:
        return "İndirilenler klasöründen"
    if any(p.startswith(".") and p not in (".", "..") for p in Path(yol).parts[1:-1]):
        return "gizli bir klasörden"
    return None


def baslangic_ogesi_analiz(yol: Path) -> Optional[Sonuc]:
    """macOS LaunchAgent/LaunchDaemon plist'ini ve Linux autostart .desktop dosyasını inceler."""
    bulgular: List[Bulgu] = []
    program, argumanlar, etiket = "", "", yol.stem
    try:
        if yol.suffix == ".plist":
            with open(yol, "rb") as f:
                p = plistlib.load(f)
            etiket = str(p.get("Label", yol.stem))
            args = p.get("ProgramArguments") or []
            program = str(p.get("Program") or (args[0] if args else ""))
            argumanlar = " ".join(str(a) for a in args)
        elif yol.suffix == ".desktop":
            for satir in yol.read_text(errors="replace").splitlines():
                if satir.startswith("Exec="):
                    argumanlar = satir[5:]
                    program = argumanlar.split()[0] if argumanlar.split() else ""
        else:
            return None
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None

    komut = f"{program} {argumanlar}"
    konum = _gizli_konum(program)
    if konum:
        bulgular.append(Bulgu("baslangic_gizli_konum", f"Açılışta {konum} bir program başlatıyor: {program}", 50, "zararli"))
    for desen, aciklama in _TEHLIKELI_KOMUT:
        if re.search(desen, komut, re.I):
            bulgular.append(Bulgu("baslangic_tehlikeli_komut", f"Açılışta çalışan komut: {aciklama}.", 65, "zararli"))
            break
    if etiket.startswith("com.apple.") and str(EV) in str(yol):
        bulgular.append(Bulgu("baslangic_apple_taklidi",
                              "Kullanıcı klasöründe 'com.apple.' adlı başlangıç öğesi: Apple'ın kendi öğeleri burada bulunmaz.",
                              45, "zararli"))
    if not bulgular:
        return None
    s = Sonuc("baslangic", str(yol), kaynak="sistem", bulgular=bulgular)
    s.ek.update({"etiket": etiket, "program": program[:300], "komut": komut[:500]})
    return sonuclandir(s)


# ---------------------------------------------------------------------------
# Tarama işi
# ---------------------------------------------------------------------------
def _yeni_is(tur: str, hedefler: List[Tuple[Path, int]]) -> Dict[str, Any]:
    return {
        "id": uuid.uuid4().hex[:12], "tur": tur, "durum": "calisiyor", "hedefler": [str(h) for h, _ in hedefler],
        "taranan": 0, "derin": 0, "erisilemeyen": 0, "bulutta": 0, "konum": "", "bulgular": [],
        "baslangic": time.time(), "bitis": None,
    }


def _kaydet(sonuc: Sonuc, is_: Dict[str, Any], yol: Path) -> None:
    from . import service

    kayit = service.sonuc_isle(sonuc)
    if sonuc.seviye != "guvenli":
        is_["bulgular"].append({
            "no": len(is_["bulgular"]), "yol": str(yol), "tur": sonuc.tur, "puan": sonuc.puan, "seviye": sonuc.seviye,
            "kategori": sonuc.kategori, "sha256": sonuc.ek.get("sha256"), "kayit_id": kayit.get("id"),
            "nedenler": [b.aciklama for b in sorted(sonuc.bulgular, key=lambda b: -b.agirlik)[:3]],
            "karantina": None,
        })


def calistir(is_: Dict[str, Any], hedefler: List[Tuple[Path, int]]) -> None:
    sinir = config.MAX_DOSYA_MB * 1024 * 1024
    try:
        for kok, derinlik in hedefler:
            baslangic_klasoru = kok.name in BASLANGIC_ADLARI
            for yol in _dosyalar(kok, derinlik, is_):
                if is_.get("iptal"):
                    is_["durum"] = "iptal"
                    return
                if is_["taranan"] >= AZAMI_DOSYA:
                    break
                is_["taranan"] += 1
                try:
                    st = yol.lstat()
                    if not stat.S_ISREG(st.st_mode):  # bağlantı, soket, FIFO (FIFO okumak sonsuza kadar bekletir)
                        continue
                    if getattr(st, "st_flags", 0) & SF_DATALESS:
                        # iCloud/OneDrive'da duran yer tutucu: okumak dosyayı buluttan indirtir ve taramayı kilitler
                        is_["bulutta"] += 1
                        continue
                    if baslangic_klasoru:
                        s = baslangic_ogesi_analiz(yol)
                        if s:
                            _kaydet(s, is_, yol)
                        continue
                    if not _derin_mi(yol):
                        continue
                    boyut = st.st_size
                    if boyut == 0 or boyut > sinir:
                        continue
                    is_["derin"] += 1
                    s = dosya_analiz(yol.read_bytes(), yol.name, kaynak="sistem", baglam="sistem")
                    s.hedef = str(yol)[:300]
                    _kaydet(s, is_, yol)
                except PermissionError:
                    is_["erisilemeyen"] += 1
                except OSError:
                    continue
        is_["durum"] = "bitti"
    except Exception as e:  # beklenmeyen hata işi askıda bırakmasın
        is_.update(durum="hata", hata=f"{type(e).__name__}: {e}")
    finally:
        is_["bitis"] = time.time()
        is_["konum"] = ""
        _son_tarama_yaz(is_)
        _ozet_bildir(is_)


def _ozet_bildir(is_: Dict[str, Any]) -> None:
    from .alerts import yayinci

    yayinci.yayinla({"tip": "sistem_tarama", "veri": durum(is_["id"], ozet_only=True)})


def baslat(tur: str, klasor: Optional[str] = None) -> str:
    if tur == "hizli":
        hedefler = hizli_konumlar()
    elif tur == "tam":
        hedefler = [(EV, 64)] + [(k, d) for k, d in hizli_konumlar()
                                 if k.name in BASLANGIC_ADLARI or not str(k).startswith(str(EV))]
    else:
        k = Path(klasor or "").expanduser()
        if not k.is_dir():
            raise ValueError("Klasör bulunamadı")
        hedefler = [(k.resolve(), 64)]
    with _kilit:
        if any(i["durum"] == "calisiyor" for i in _isler.values()):
            raise RuntimeError("Zaten çalışan bir bilgisayar taraması var")
        is_ = _yeni_is(tur, hedefler)
        _isler[is_["id"]] = is_
        if len(_isler) > 10:
            _isler.pop(sorted(_isler, key=lambda k: _isler[k]["baslangic"])[0], None)
    threading.Thread(target=calistir, args=(is_, hedefler), name="sistem-tarama", daemon=True).start()
    return is_["id"]


def durum(is_id: str, ozet_only: bool = False) -> Optional[Dict[str, Any]]:
    is_ = _isler.get(is_id)
    if not is_:
        return None
    d = {k: v for k, v in is_.items() if k != "bulgular"}
    d["uyari"] = len(is_["bulgular"])
    d["tehlikeli"] = sum(1 for b in is_["bulgular"] if b["seviye"] == "tehlikeli")
    if not ozet_only:
        d["bulgular"] = sorted(is_["bulgular"], key=lambda b: -b["puan"])
    return d


def son_is() -> Optional[Dict[str, Any]]:
    if not _isler:
        return None
    return durum(max(_isler, key=lambda k: _isler[k]["baslangic"]))


def iptal(is_id: str) -> bool:
    if is_id in _isler:
        _isler[is_id]["iptal"] = True
        return True
    return False


def bulgu(is_id: str, no: int) -> Optional[Dict[str, Any]]:
    is_ = _isler.get(is_id)
    if not is_ or not (0 <= no < len(is_["bulgular"])):
        return None
    return is_["bulgular"][no]


# Son otomatik taramanın zamanı (sunucu yeniden başlayınca her seferinde tarama yapılmasın)
def _son_tarama_dosyasi() -> Path:
    return config.DATA_DIR / "son_sistem_taramasi.txt"


def _son_tarama_yaz(is_: Dict[str, Any]) -> None:
    if is_["durum"] == "bitti":
        try:
            _son_tarama_dosyasi().write_text(f"{is_['bitis']}\n{is_['tur']}\n{is_['taranan']}\n{len(is_['bulgular'])}")
        except OSError:
            pass


def son_tarama() -> Optional[Dict[str, Any]]:
    try:
        z, tur, taranan, uyari = _son_tarama_dosyasi().read_text().split("\n")[:4]
        return {"zaman": float(z), "tur": tur, "taranan": int(taranan), "uyari": int(uyari)}
    except (OSError, ValueError):
        return None


def otomatik_dongu(durdur: threading.Event) -> None:
    """Belirli aralıkla hızlı tarama. Açılıştan 10 dk sonra ilk kontrol; son taramadan bu yana süre dolduysa çalışır."""
    aralik = config.OTOMATIK_TARAMA_SAAT * 3600
    if durdur.wait(600):
        return
    while True:
        son = son_tarama()
        if not son or time.time() - son["zaman"] >= aralik:
            try:
                baslat("hizli")
            except RuntimeError:
                pass
        if durdur.wait(min(aralik, 3600)):
            return


def main() -> None:
    import sys

    from . import store

    config.LLM_ENABLED = False
    store.hazirla()
    arg = sys.argv[1] if len(sys.argv) > 1 else "hizli"
    is_id = baslat(arg if arg in ("hizli", "tam") else "klasor", None if arg in ("hizli", "tam") else arg)
    while _isler[is_id]["durum"] == "calisiyor":
        time.sleep(1)
        i = _isler[is_id]
        print(f"\rTaranan: {i['taranan']}  Derin: {i['derin']}  Uyarı: {len(i['bulgular'])}", end="", flush=True)
    d = durum(is_id)
    print(f"\n{d['durum']}: {d['taranan']} dosya, {d['derin']} derin analiz, {d['erisilemeyen']} erişilemedi")
    for b in d["bulgular"]:
        print(f"{b['puan']:3} {b['seviye']:9} {b['yol']}\n     {'; '.join(b['nedenler'])}")


if __name__ == "__main__":
    main()
