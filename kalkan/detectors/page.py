"""Tarayıcıda açık sayfanın analizi (Chrome eklentisinden gelir).

Adres analizine ek olarak sayfanın kendisine bakar: tanınmış bir markanın adını taşıyan ama o markanın
alan adında olmayan bir şifre formu, sahte giriş sayfasının en güçlü işaretidir.
Sayfa metni yalnızca analiz için kullanılır, kaydedilmez.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from ..models import Bulgu, Sonuc, sonuclandir
from .text import MARKA_ADLARI, _norm
from .url import RESMI_ALANLAR, _kok_alan, url_analiz


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def sayfa_analiz(
    url: str,
    baslik: str = "",
    metin: str = "",
    formlar: Optional[List[Dict[str, Any]]] = None,
    kaynak: str = "tarayici",
) -> Sonuc:
    formlar = formlar or []
    temel = url_analiz(url, kaynak=kaynak)
    sonuc = Sonuc("sayfa", url[:200], kaynak=kaynak, bulgular=list(temel.bulgular), ml=temel.ml)
    sonuc.ek.update({k: v for k, v in temel.ek.items()})
    sonuc.ek["baslik"] = (baslik or "")[:120]

    guvenilir = bool(temel.ek.get("guvenilir_alan"))
    kok = temel.ek.get("kok_alan") or _kok_alan(_host(url))
    sifreli_formlar = [f for f in formlar if f.get("sifre")]
    sonuc.ek["sifre_formu"] = bool(sifreli_formlar)

    if sifreli_formlar and not guvenilir:
        # Başlık ve görünen metinde marka adı var mı?
        n = _norm(f"{baslik}\n{metin[:5000]}")
        for marka, resmi in MARKA_ADLARI.items():
            if re.search(rf"\b{re.escape(marka)}\b", n) and kok != resmi and not str(kok).endswith("." + resmi):
                sonuc.bulgular.append(Bulgu(
                    "sahte_giris_sayfasi",
                    f"Sayfa '{RESMI_ALANLAR.get(resmi, marka)}' adını taşıyor ve şifre istiyor, ama adres {_host(url)}; "
                    f"resmî adres {resmi}.",
                    75, "phishing",
                ))
                break

        for f in sifreli_formlar:
            hedef = _host(str(f.get("action") or ""))
            if hedef and _kok_alan(hedef) != kok:
                sonuc.bulgular.append(Bulgu(
                    "form_baska_alana",
                    f"Şifre formu bilgileri başka bir alan adına ({hedef}) gönderiyor.",
                    35, "phishing",
                ))
                break
        if url.lower().startswith("http://"):
            sonuc.bulgular.append(Bulgu("sifresiz_giris", "Şifre şifrelenmemiş (http) bir sayfada isteniyor.", 30, "phishing"))
        if any(f.get("kart") for f in formlar):
            sonuc.bulgular.append(Bulgu("kart_formu", "Sayfa tanınmış olmayan bir alanda kart bilgisi istiyor.", 25, "phishing"))

    return sonuclandir(sonuc)
