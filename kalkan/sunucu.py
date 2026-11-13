"""Kalkan arka plan servisi: yalnızca bu bilgisayardan erişilebilen yerel sunucuyu başlatır.

Kalkan.app kurulduğunda macOS bunu oturum açılışında otomatik çalıştırır (LaunchAgent).
Elle:  python -m kalkan.sunucu
"""
from __future__ import annotations

import uvicorn

from . import config


def main() -> None:
    # 127.0.0.1: sunucu ağdaki başka bilgisayarlardan erişilemez
    uvicorn.run("kalkan.main:app", host="127.0.0.1", port=config.PORT, log_level="info")


if __name__ == "__main__":
    main()
