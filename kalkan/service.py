"""Tarama akışı: dedektör -> (isteğe bağlı) LLM -> kayıt -> uyarı. API, eklenti ve izleyiciler bunu kullanır."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import alerts, config, llm, store
from .detectors.file import dosya_analiz
from .detectors.image import gorsel_analiz
from .detectors.page import sayfa_analiz
from .detectors.text import metin_analiz
from .detectors.url import url_analiz

# Bu kaynaklardan gelen içerik dış API'ye (Claude) gönderilmez:
# gezinme geçmişi ve toplu e-postalar kişisel veri yoğundur, toplu işte maliyet de kontrolsüz büyür.
LLM_DISI_KAYNAKLAR = {"tarayici", "toplu", "klasor"}


def _tamamla(sonuc, icerik_llm: Optional[str], yalniz_uyari_kaydet: bool = False) -> Dict[str, Any]:
    if sonuc.kaynak not in LLM_DISI_KAYNAKLAR:
        sonuc = llm.birlestir(sonuc, llm.degerlendir(sonuc, icerik_llm))
    store.say(sonuc.tur, sonuc.seviye)
    if yalniz_uyari_kaydet and sonuc.seviye == "guvenli":
        kayit = sonuc.to_dict()
        kayit["id"] = None
        return kayit
    kayit = store.kaydet(sonuc)
    alerts.bildir(kayit)
    return kayit


def metin_tara(icerik: str, tur: str, kaynak: str = "panel", yalniz_uyari_kaydet: bool = False) -> Dict[str, Any]:
    return _tamamla(metin_analiz(icerik, tur=tur, kaynak=kaynak), icerik, yalniz_uyari_kaydet)


def url_tara(url: str, kaynak: str = "panel", yalniz_uyari_kaydet: bool = False) -> Dict[str, Any]:
    return _tamamla(url_analiz(url, kaynak=kaynak), url, yalniz_uyari_kaydet)


def dosya_tara(veri: bytes, ad: str, kaynak: str = "panel", yalniz_uyari_kaydet: bool = False) -> Dict[str, Any]:
    # Dosya içeriği LLM'e gönderilmez; yalnızca bulgular ve meta veri gider.
    return _tamamla(dosya_analiz(veri, ad, kaynak=kaynak), None, yalniz_uyari_kaydet)


def gorsel_tara(veri: bytes, ad: str, kaynak: str = "panel") -> Dict[str, Any]:
    return _tamamla(gorsel_analiz(veri, ad, kaynak=kaynak), None)


def sayfa_tara(url: str, baslik: str, metin: str, formlar: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Tarayıcı eklentisinden. Yalnızca uyarılar geçmişe yazılır; sayfa metni hiç saklanmaz."""
    return _tamamla(sayfa_analiz(url, baslik, metin, formlar), None, yalniz_uyari_kaydet=True)


def indirme_dizini() -> Path:
    return Path(config.INDIRME_DIZINI).expanduser().resolve()


def indirme_tara(yol: str, kaynak_url: str = "") -> Dict[str, Any]:
    """Tarayıcının indirdiği dosyayı diskten okuyup tarar.

    Güvenlik: yalnızca İndirilenler klasörünün içindeki dosyalar okunur. Aksi hâlde bu uç nokta
    yerel diskteki herhangi bir dosyayı okutmak için kötüye kullanılabilirdi.
    """
    hedef = Path(yol).expanduser().resolve()
    kok = indirme_dizini()
    if os.path.commonpath([str(hedef), str(kok)]) != str(kok) or not hedef.is_file():
        raise PermissionError("Yalnızca İndirilenler klasöründeki dosyalar taranabilir")
    if hedef.stat().st_size > config.MAX_DOSYA_MB * 1024 * 1024:
        raise ValueError("Dosya boyut sınırını aşıyor")
    sonuc = dosya_analiz(hedef.read_bytes(), hedef.name, kaynak="tarayici")
    if kaynak_url:
        u = url_analiz(kaynak_url, kaynak="tarayici")
        sonuc.ek["indirme_adresi"] = kaynak_url[:300]
        if u.seviye != "guvenli":
            from .models import Bulgu, sonuclandir
            sonuc.bulgular.append(Bulgu("riskli_kaynak", f"Dosya riskli bir adresten indirildi (puan {u.puan}).",
                                        u.puan // 2, "zararli"))
            sonuc = sonuclandir(sonuc)
    return _tamamla(sonuc, None, yalniz_uyari_kaydet=False)
