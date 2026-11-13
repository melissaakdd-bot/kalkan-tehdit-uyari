const VARSAYILAN = { sunucu: "http://127.0.0.1:8790", token: "", aktif: true, indirmeler: true };
const SEVIYE = { tehlikeli: "Tehlikeli", supheli: "Şüpheli", guvenli: "Sorun bulunmadı" };
const KATEGORI = { phishing: "Oltalama (phishing)", spam: "Spam", zararli: "Zararlı yazılım", supheli: "Şüpheli içerik" };

function el(etiket, sinif, metin) {
  const e = document.createElement(etiket);
  if (sinif) e.className = sinif;
  if (metin) e.textContent = metin;
  return e;
}

(async () => {
  const a = Object.assign({}, VARSAYILAN, await chrome.storage.sync.get(Object.keys(VARSAYILAN)));
  const aktif = document.getElementById("aktif");
  const indirmeler = document.getElementById("indirmeler");
  aktif.checked = a.aktif;
  indirmeler.checked = a.indirmeler;
  aktif.onchange = () => chrome.storage.sync.set({ aktif: aktif.checked });
  indirmeler.onchange = () => chrome.storage.sync.set({ indirmeler: indirmeler.checked });
  document.getElementById("panel").onclick = () => chrome.tabs.create({ url: a.sunucu });

  chrome.runtime.sendMessage({ tip: "sunucu_durumu" }, (y) => {
    document.getElementById("sunucu").textContent = y && y.ok ? "● sunucu bağlı" : "○ sunucuya ulaşılamıyor";
  });

  const [sekme] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!sekme) return;
  const kayit = (await chrome.storage.session.get("sekme_" + sekme.id))["sekme_" + sekme.id];
  const kutu = document.getElementById("sonuc");
  if (!kayit) return;
  kutu.textContent = "";
  if (kayit.hata) {
    kutu.className = "kutu hata";
    kutu.append(el("div", "seviye", kayit.hata), el("div", "adres", "Kalkan sunucusunun çalıştığını ve ayarlardaki adresi kontrol edin."));
    return;
  }
  kutu.className = "kutu " + kayit.seviye;
  const baslik = SEVIYE[kayit.seviye] + (kayit.seviye !== "guvenli" ? ` · ${KATEGORI[kayit.kategori] || kayit.kategori} · ${kayit.puan}/100` : "");
  kutu.append(el("div", "seviye", baslik), el("div", "adres", kayit.url));
  if (kayit.nedenler && kayit.nedenler.length) {
    const ul = el("ul");
    kayit.nedenler.forEach((n) => ul.appendChild(el("li", "", n)));
    kutu.appendChild(ul);
  }
})();
