const VARSAYILAN = { sunucu: "http://127.0.0.1:8790", token: "" };

(async () => {
  const a = Object.assign({}, VARSAYILAN, await chrome.storage.sync.get(Object.keys(VARSAYILAN)));
  const sunucu = document.getElementById("sunucu");
  const token = document.getElementById("token");
  const bilgi = document.getElementById("bilgi");
  sunucu.value = a.sunucu;
  token.value = a.token;

  document.getElementById("kaydet").onclick = async () => {
    let adres = sunucu.value.trim().replace(/\/$/, "");
    let url;
    try { url = new URL(adres); } catch (_) { bilgi.textContent = "Geçersiz adres"; return; }
    // Eklentinin izinleri yalnızca yerel sunucuyu kapsar; sayfa verisi başka bir makineye gönderilmez
    if (!["127.0.0.1", "localhost"].includes(url.hostname) || url.protocol !== "http:") {
      bilgi.textContent = "Yalnızca http://127.0.0.1 ya da http://localhost adresleri desteklenir";
      return;
    }
    await chrome.storage.sync.set({ sunucu: adres, token: token.value.trim() });
    chrome.runtime.sendMessage({ tip: "onbellegi_temizle" });
    bilgi.textContent = "Bağlantı deneniyor…";
    try {
      const r = await fetch(adres + "/api/durum");
      const d = await r.json();
      bilgi.textContent = `Bağlandı (Kalkan ${d.surum || ""})`;
    } catch (_) {
      bilgi.textContent = "Kaydedildi ama sunucuya ulaşılamadı. Kalkan çalışıyor mu?";
    }
  };
})();
