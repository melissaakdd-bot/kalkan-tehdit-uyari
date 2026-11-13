"""Değerlendirme sonuçlarını okunur tabloya çevirir."""
from __future__ import annotations

from typing import Dict, Optional

MOD_ADI = {"kural": "Yalnız kurallar", "ml": "Yalnız ML (0,5 eşiği)", "hibrit": "Kalkan (gerçek karar)"}
GRUP_ADI = {"eposta": "E-posta", "sms": "SMS", "url": "URL"}


def _yuzde(v: Optional[float]) -> str:
    return "—" if v is None else f"%{v * 100:.1f}"


def konsola_yaz(sonuc: Dict) -> None:
    print(f"\nTest örneği: {sonuc['ornek_sayisi']}   Ortalama süre: {sonuc['ortalama_ms']} ms/örnek")
    for grup, modlar in sorted(sonuc["metrikler"].items()):
        if ":" in grup:
            continue
        print(f"\n== {GRUP_ADI.get(grup, grup)} ==")
        print(f"{'Mod':38} {'Tespit':>8} {'Yanlış alarm':>13} {'Kesinlik':>9} {'F1':>7}  (TP/FP/TN/FN)")
        for mod in ("kural", "ml", "hibrit"):
            m = modlar.get(mod)
            if not m:
                continue
            print(f"{MOD_ADI[mod]:38} {_yuzde(m['tespit_orani']):>8} {_yuzde(m['yanlis_alarm']):>13} "
                  f"{_yuzde(m['kesinlik']):>9} {_yuzde(m['f1']):>7}  ({m['tp']}/{m['fp']}/{m['tn']}/{m['fn']})")
        alt = [(g, v["hibrit"]) for g, v in sonuc["metrikler"].items() if g.startswith(grup + ":") and "hibrit" in v]
        for g, m in sorted(alt):
            print(f"   {g.split(':', 1)[1]:35} tespit {_yuzde(m['tespit_orani'])}  yanlış alarm {_yuzde(m['yanlis_alarm'])}"
                  f"  (TP/FP/TN/FN {m['tp']}/{m['fp']}/{m['tn']}/{m['fn']})")
    print("\nTehdit kategorisi doğruluğu (yakalananlar arasında):",
          {k: _yuzde(v) for k, v in sonuc["kategori_dogrulugu"].items()})
