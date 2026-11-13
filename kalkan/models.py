"""Tarama sonucu veri yapıları ve puanlama."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from . import config

SEVIYELER = ("guvenli", "supheli", "tehlikeli")


@dataclass
class Bulgu:
    """Tek bir tespit sinyali."""

    kod: str
    aciklama: str
    agirlik: int  # 0-100 arası katkı
    kategori: str = "genel"  # phishing | spam | zararli | genel
    kritik: bool = False  # tek başına "tehlikeli" sonucunu zorlar


@dataclass
class Sonuc:
    tur: str  # eposta | sms | url | dosya
    hedef: str  # panelde gösterilecek kısa etiket (içeriğin tamamı saklanmaz)
    puan: int = 0
    seviye: str = "guvenli"
    kategori: str = "temiz"
    bulgular: List[Bulgu] = field(default_factory=list)
    ml: Optional[Dict[str, Any]] = None
    llm: Optional[Dict[str, Any]] = None
    ek: Dict[str, Any] = field(default_factory=dict)
    kaynak: str = "panel"  # panel | klasor | imap | api

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def kural_puani(bulgular: List[Bulgu]) -> int:
    """Ağırlıkları doygunlukla birleştirir: her sinyal kalan boşluğun bir kısmını doldurur.

    Böylece çok sayıda zayıf sinyal 100'ü aşmaz, güçlü bir sinyal tek başına yüksek puan verir.
    """
    kalan = 1.0
    for b in bulgular:
        kalan *= 1 - min(max(b.agirlik, 0), 100) / 100
    return round((1 - kalan) * 100)


def baskin_kategori(bulgular: List[Bulgu], varsayilan: str = "temiz") -> str:
    toplam: Dict[str, int] = {}
    for b in bulgular:
        if b.kategori != "genel":
            toplam[b.kategori] = toplam.get(b.kategori, 0) + b.agirlik
    if not toplam:
        return varsayilan
    return max(toplam.items(), key=lambda kv: kv[1])[0]


def seviye_belirle(puan: int, bulgular: List[Bulgu]) -> str:
    if any(b.kritik for b in bulgular) or puan >= config.TEHLIKELI_ESIK:
        return "tehlikeli"
    if puan >= config.SUPHELI_ESIK:
        return "supheli"
    return "guvenli"


def sonuclandir(sonuc: Sonuc) -> Sonuc:
    """Bulgulardan risk puanını ve seviyeyi belirler.

    ML modelleri de puana doğrudan karışmaz; yüksek güvende açıklamalı bir bulgu (ml_metin, ml_url) ekler.
    Böylece her uyarının nedeni kullanıcıya gösterilebilir.
    """
    puan = kural_puani(sonuc.bulgular)
    if any(b.kritik for b in sonuc.bulgular):
        puan = max(puan, 95)
    sonuc.puan = min(puan, 100)
    sonuc.seviye = seviye_belirle(sonuc.puan, sonuc.bulgular)
    if sonuc.seviye == "guvenli":
        sonuc.kategori = "temiz"
    else:
        ml_kat = (sonuc.ml or {}).get("etiket")
        varsayilan = ml_kat if ml_kat and ml_kat != "temiz" else "supheli"
        sonuc.kategori = baskin_kategori(sonuc.bulgular, varsayilan)
    return sonuc
