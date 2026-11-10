"""Arka plan izleyicileri: klasöre düşen yeni dosyalar ve IMAP posta kutusuna gelen yeni e-postalar.

İkisi de yalnızca ortam değişkenleri tanımlıysa çalışır. IMAP izleyici e-postaları "okundu" işaretlemez
(BODY.PEEK) ve hiçbir şeyi silmez ya da taşımaz.
"""
from __future__ import annotations

import imaplib
import logging
import threading
import time
from pathlib import Path
from typing import Dict, Set, Tuple

from . import config, service

log = logging.getLogger("kalkan.watchers")
_durdur = threading.Event()


def _klasor_izle() -> None:
    kok = Path(config.WATCH_DIR).expanduser()
    if not kok.is_dir():
        log.warning("İzlenecek klasör bulunamadı: %s", kok)
        return
    log.info("Klasör izleniyor: %s", kok)

    def anlik() -> Dict[Path, Tuple[float, int]]:
        sonuc = {}
        for p in kok.iterdir():
            # Tarayıcıların yarım indirme dosyalarını atla
            if p.is_file() and not p.name.startswith(".") and p.suffix not in (".crdownload", ".part", ".download"):
                st = p.stat()
                sonuc[p] = (st.st_mtime, st.st_size)
        return sonuc

    gorulen = anlik()  # başlangıçtaki dosyalar taranmaz, yalnızca yeni gelenler
    bekleyen: Dict[Path, Tuple[float, int]] = {}
    while not _durdur.wait(config.WATCH_INTERVAL):
        try:
            simdi = anlik()
        except OSError as e:
            log.warning("Klasör okunamadı: %s", e)
            continue
        for p, imza in simdi.items():
            if gorulen.get(p) == imza:
                continue
            # Dosya yazımı bitmiş olsun: iki tur boyunca boyutu değişmemeli
            if bekleyen.get(p) != imza:
                bekleyen[p] = imza
                continue
            bekleyen.pop(p, None)
            gorulen[p] = imza
            if imza[1] > config.MAX_DOSYA_MB * 1024 * 1024:
                log.info("Boyut sınırını aşan dosya atlandı: %s", p.name)
                continue
            try:
                service.dosya_tara(p.read_bytes(), p.name, kaynak="klasor")
            except OSError as e:
                log.warning("Dosya okunamadı %s: %s", p, e)


def _imap_izle() -> None:
    gorulen: Set[bytes] = set()
    ilk = True
    while not _durdur.is_set():
        try:
            with imaplib.IMAP4_SSL(config.IMAP_HOST) as imap:
                imap.login(config.IMAP_USER, config.IMAP_PASSWORD)
                imap.select(config.IMAP_FOLDER, readonly=True)
                log.info("IMAP bağlantısı kuruldu: %s/%s", config.IMAP_HOST, config.IMAP_FOLDER)
                while not _durdur.is_set():
                    durum, veri = imap.uid("search", None, "UNSEEN")
                    if durum == "OK":
                        uidler = veri[0].split()
                        if ilk:  # açılışta yalnızca son 20 okunmamış taranır, eskiler uyarı yağmuruna dönmesin
                            gorulen.update(uidler[:-20])
                            ilk = False
                        for uid in uidler:
                            if uid in gorulen:
                                continue
                            gorulen.add(uid)
                            durum, parca = imap.uid("fetch", uid, "(BODY.PEEK[])")
                            if durum == "OK" and parca and isinstance(parca[0], tuple):
                                ham = parca[0][1].decode("utf-8", errors="replace")
                                service.metin_tara(ham, "eposta", kaynak="imap")
                    if _durdur.wait(config.IMAP_INTERVAL):
                        break
                    imap.noop()
        except (imaplib.IMAP4.error, OSError) as e:
            log.warning("IMAP hatası: %s. 60 sn sonra yeniden denenecek.", e)
            if _durdur.wait(60):
                break


def baslat() -> None:
    if config.WATCH_DIR:
        threading.Thread(target=_klasor_izle, name="klasor-izleyici", daemon=True).start()
    if config.IMAP_HOST and config.IMAP_USER and config.IMAP_PASSWORD:
        threading.Thread(target=_imap_izle, name="imap-izleyici", daemon=True).start()


def durdur() -> None:
    _durdur.set()
