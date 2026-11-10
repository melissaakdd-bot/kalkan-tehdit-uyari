"""Tarama akışı: dedektör -> (isteğe bağlı) LLM -> kayıt -> uyarı. API ve izleyiciler bunu kullanır."""
from __future__ import annotations

from typing import Any, Dict

from . import alerts, llm, store
from .detectors.file import dosya_analiz
from .detectors.text import metin_analiz
from .detectors.url import url_analiz


def _tamamla(sonuc, icerik_llm) -> Dict[str, Any]:
    sonuc = llm.birlestir(sonuc, llm.degerlendir(sonuc, icerik_llm))
    kayit = store.kaydet(sonuc)
    alerts.bildir(kayit)
    return kayit


def metin_tara(icerik: str, tur: str, kaynak: str = "panel") -> Dict[str, Any]:
    return _tamamla(metin_analiz(icerik, tur=tur, kaynak=kaynak), icerik)


def url_tara(url: str, kaynak: str = "panel") -> Dict[str, Any]:
    return _tamamla(url_analiz(url, kaynak=kaynak), url)


def dosya_tara(veri: bytes, ad: str, kaynak: str = "panel") -> Dict[str, Any]:
    # Dosya içeriği LLM'e gönderilmez; yalnızca bulgular ve meta veri gider.
    return _tamamla(dosya_analiz(veri, ad, kaynak=kaynak), None)
