// Kalkan Koruma: arka plan servisi.
// Sayfa ve indirme taramalarını yerel Kalkan sunucusuna iletir, sonuca göre rozet, bildirim ve uyarı gösterir.
// Veriler yalnızca ayarlardaki sunucuya (varsayılan 127.0.0.1) gönderilir.

const VARSAYILAN = { sunucu: "http://127.0.0.1:8765", token: "", aktif: true, indirmeler: true };
const ONBELLEK_MS = 10 * 60 * 1000;
const onbellek = new Map(); // url -> { sonuc, zaman }
const bildirilen = new Map(); // host -> zaman (aynı site için 30 dk'da bir bildirim)

async function ayarlar() {
  return Object.assign({}, VARSAYILAN, await chrome.storage.sync.get(Object.keys(VARSAYILAN)));
}

async function istek(yol, govde) {
  const a = await ayarlar();
  const basliklar = { "Content-Type": "application/json" };
  if (a.token) basliklar["X-Kalkan-Token"] = a.token;
  const r = await fetch(a.sunucu.replace(/\/$/, "") + yol, { method: "POST", headers: basliklar, body: JSON.stringify(govde) });
  if (!r.ok) {
    const hata = new Error(`HTTP ${r.status}`);
    hata.durum = r.status;
    throw hata;
  }
  return r.json();
}

function rozet(tabId, seviye) {
  const ayar = {
    tehlikeli: { text: "!", color: "#c42b2b", title: "Kalkan: tehlikeli sayfa" },
    supheli: { text: "?", color: "#d08a00", title: "Kalkan: şüpheli sayfa" },
    guvenli: { text: "", color: "#1d8a4e", title: "Kalkan: sorun bulunmadı" },
    hata: { text: "–", color: "#7a808a", title: "Kalkan sunucusuna bağlanılamadı" },
    kapali: { text: "", color: "#7a808a", title: "Kalkan: otomatik koruma kapalı" },
  }[seviye];
  chrome.action.setBadgeText({ tabId, text: ayar.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: ayar.color });
  chrome.action.setTitle({ tabId, title: ayar.title });
}

const SEVIYE = { tehlikeli: "Tehlikeli", supheli: "Şüpheli", guvenli: "Güvenli" };
const KATEGORI = { phishing: "oltalama (phishing)", spam: "spam", zararli: "zararlı yazılım", supheli: "şüpheli içerik" };

function bildir(baslik, mesaj, anahtar) {
  const simdi = Date.now();
  if (anahtar && bildirilen.has(anahtar) && simdi - bildirilen.get(anahtar) < 30 * 60 * 1000) return;
  if (anahtar) bildirilen.set(anahtar, simdi);
  chrome.notifications.create({ type: "basic", iconUrl: "ikon128.png", title: baslik, message: mesaj, priority: 2 });
}

async function sayfaTara(veri, tabId) {
  const a = await ayarlar();
  if (!a.aktif) { rozet(tabId, "kapali"); return null; }
  // Kalkan panelinin kendisini tarama
  try { if (new URL(veri.url).origin === new URL(a.sunucu).origin) return null; } catch (_) { return null; }

  const anahtar = veri.url + "|" + (veri.formlar || []).length;
  const kayit = onbellek.get(anahtar);
  let sonuc;
  if (kayit && Date.now() - kayit.zaman < ONBELLEK_MS) {
    sonuc = kayit.sonuc;
  } else {
    try {
      sonuc = await istek("/api/tara/sayfa", veri);
      onbellek.set(anahtar, { sonuc, zaman: Date.now() });
      if (onbellek.size > 500) onbellek.delete(onbellek.keys().next().value);
    } catch (e) {
      rozet(tabId, "hata");
      await chrome.storage.session.set({ ["sekme_" + tabId]: { hata: e.durum === 401 ? "Erişim anahtarı geçersiz" : "Sunucuya bağlanılamadı", url: veri.url } });
      return null;
    }
  }
  rozet(tabId, sonuc.seviye);
  const ozet = {
    url: veri.url, puan: sonuc.puan, seviye: sonuc.seviye, kategori: sonuc.kategori,
    nedenler: (sonuc.bulgular || []).sort((x, y) => y.agirlik - x.agirlik).slice(0, 4).map((b) => b.aciklama),
  };
  await chrome.storage.session.set({ ["sekme_" + tabId]: ozet });
  if (sonuc.seviye === "tehlikeli") {
    let host = "";
    try { host = new URL(veri.url).hostname; } catch (_) {}
    bildir(`Kalkan: tehlikeli sayfa (${KATEGORI[sonuc.kategori] || sonuc.kategori})`, `${host}\n${ozet.nedenler[0] || ""}`, "sayfa:" + host);
  }
  return ozet;
}

chrome.runtime.onMessage.addListener((mesaj, gonderen, yanitla) => {
  if (mesaj.tip === "sayfa" && gonderen.tab) {
    sayfaTara(mesaj.veri, gonderen.tab.id).then(yanitla);
    return true; // async yanıt
  }
  if (mesaj.tip === "sekmeyi_kapat" && gonderen.tab) {
    chrome.tabs.remove(gonderen.tab.id);
  }
  if (mesaj.tip === "sunucu_durumu") {
    ayarlar().then((a) => fetch(a.sunucu.replace(/\/$/, "") + "/api/durum").then((r) => r.json()))
      .then((d) => yanitla({ ok: true, durum: d })).catch(() => yanitla({ ok: false }));
    return true;
  }
  if (mesaj.tip === "onbellegi_temizle") {
    onbellek.clear();
    yanitla({ ok: true });
  }
});

// İndirmeler: tamamlanınca dosya yolu yerel sunucuya bildirilir, sunucu dosyayı İndirilenler'den okuyup tarar.
chrome.downloads.onChanged.addListener(async (degisim) => {
  if (!degisim.state || degisim.state.current !== "complete") return;
  const a = await ayarlar();
  if (!a.aktif || !a.indirmeler) return;
  const [oge] = await chrome.downloads.search({ id: degisim.id });
  if (!oge || !oge.filename) return;
  try {
    const sonuc = await istek("/api/tara/indirme", { yol: oge.filename, url: oge.finalUrl || oge.url || "" });
    if (sonuc.seviye !== "guvenli") {
      const ad = oge.filename.split(/[\\/]/).pop();
      const neden = (sonuc.bulgular || []).sort((x, y) => y.agirlik - x.agirlik)[0];
      bildir(`Kalkan: ${SEVIYE[sonuc.seviye]} dosya indirildi`, `${ad}\n${neden ? neden.aciklama : ""}\nDosyayı açmayın.`, "indirme:" + oge.id);
    }
  } catch (e) {
    // 403: dosya İndirilenler klasörü dışında (sunucu güvenlik gereği okumaz); diğer hatalarda sessiz kal
  }
});

chrome.notifications.onClicked.addListener(async () => {
  const a = await ayarlar();
  chrome.tabs.create({ url: a.sunucu });
});

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove("sekme_" + tabId));
