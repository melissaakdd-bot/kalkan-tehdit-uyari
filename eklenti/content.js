// Kalkan Koruma: sayfa betiği.
// Sayfanın adresini, başlığını, görünen metnin başını ve şifre/kart formlarını arka plan servisine iletir.
// Sonuç tehlikeliyse tam ekran uyarı, şüpheliyse üst çubuk gösterir. Sunucudan gelen metin yalnızca
// textContent ile basılır (sayfaya HTML enjekte edilmez).
(() => {
  if (window.top !== window) return;
  let taramaSayisi = 0;
  let gosterilen = false;

  function formlariTopla() {
    const formlar = [];
    const kartDeseni = /card|kart|cc-?num|cvv|cvc|son.?kullanma|expir/i;
    document.querySelectorAll("form").forEach((f) => {
      const sifre = !!f.querySelector('input[type="password"]');
      const kart = [...f.querySelectorAll("input")].some((i) =>
        (i.autocomplete || "").startsWith("cc-") || kartDeseni.test(`${i.name} ${i.id} ${i.placeholder}`));
      if (sifre || kart) formlar.push({ action: f.action || "", sifre, kart });
    });
    // Form etiketi olmadan duran şifre alanları (tek sayfa uygulamaları)
    if (!formlar.some((f) => f.sifre) && document.querySelector('input[type="password"]')) {
      formlar.push({ action: "", sifre: true, kart: false });
    }
    return formlar.slice(0, 50);
  }

  function tara() {
    if (taramaSayisi >= 3) return;
    taramaSayisi += 1;
    const veri = {
      url: location.href.slice(0, 8000),
      baslik: (document.title || "").slice(0, 500),
      metin: (document.body ? document.body.innerText : "").slice(0, 5000),
      formlar: formlariTopla(),
    };
    chrome.runtime.sendMessage({ tip: "sayfa", veri }, (sonuc) => {
      if (chrome.runtime.lastError || !sonuc || gosterilen) return;
      if (sonuc.seviye === "tehlikeli") tamEkranUyari(sonuc);
      else if (sonuc.seviye === "supheli") ustCubuk(sonuc);
    });
  }

  function el(etiket, stil, metin) {
    const e = document.createElement(etiket);
    if (stil) e.setAttribute("style", stil);
    if (metin) e.textContent = metin;
    return e;
  }

  const KATEGORI = { phishing: "oltalama (phishing)", spam: "spam", zararli: "zararlı yazılım", supheli: "şüpheli içerik" };

  function kapsayici() {
    const host = document.createElement("div");
    host.setAttribute("style", "all:initial");
    const kok = host.attachShadow({ mode: "closed" });
    document.documentElement.appendChild(host);
    return { host, kok };
  }

  function tamEkranUyari(s) {
    gosterilen = true;
    const { host, kok } = kapsayici();
    const perde = el("div", "position:fixed;inset:0;z-index:2147483647;background:rgba(120,10,10,.96);color:#fff;" +
      "display:flex;align-items:center;justify-content:center;padding:16px;font:16px/1.5 -apple-system,Segoe UI,Roboto,sans-serif");
    const kutu = el("div", "max-width:560px;width:100%");
    kutu.appendChild(el("div", "font-size:44px;line-height:1", "🛡️"));
    kutu.appendChild(el("h1", "font-size:26px;margin:12px 0 6px;color:#fff", "Kalkan bu sayfayı tehlikeli buldu"));
    kutu.appendChild(el("p", "margin:0 0 14px;opacity:.9",
      `Risk puanı ${s.puan}/100 · ${KATEGORI[s.kategori] || s.kategori}. Bu sayfaya şifre, kart ya da kimlik bilgisi girmeyin.`));
    const liste = el("ul", "margin:0 0 20px;padding-left:20px;opacity:.95");
    (s.nedenler || []).forEach((n) => liste.appendChild(el("li", "margin:4px 0", n)));
    kutu.appendChild(liste);
    const satir = el("div", "display:flex;gap:10px;flex-wrap:wrap");
    const geri = el("button", "background:#fff;color:#8a1515;border:0;border-radius:8px;padding:10px 18px;font:600 15px sans-serif;cursor:pointer", "Güvenli tarafa dön");
    geri.onclick = () => (history.length > 1 ? history.back() : chrome.runtime.sendMessage({ tip: "sekmeyi_kapat" }));
    const kapat = el("button", "background:transparent;color:#fff;border:1px solid rgba(255,255,255,.6);border-radius:8px;padding:10px 18px;font:15px sans-serif;cursor:pointer", "Sekmeyi kapat");
    kapat.onclick = () => chrome.runtime.sendMessage({ tip: "sekmeyi_kapat" });
    const devam = el("button", "background:transparent;color:rgba(255,255,255,.75);border:0;padding:10px 6px;font:13px sans-serif;cursor:pointer;text-decoration:underline", "Riski anlıyorum, devam et");
    devam.onclick = () => host.remove();
    satir.append(geri, kapat, devam);
    kutu.appendChild(satir);
    perde.appendChild(kutu);
    kok.appendChild(perde);
  }

  function ustCubuk(s) {
    gosterilen = true;
    const { host, kok } = kapsayici();
    const cubuk = el("div", "position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#fdf1dc;color:#5c3a00;" +
      "border-bottom:2px solid #d08a00;padding:10px 16px;display:flex;gap:12px;align-items:center;" +
      "font:14px/1.4 -apple-system,Segoe UI,Roboto,sans-serif;box-shadow:0 2px 10px rgba(0,0,0,.15)");
    const yazi = el("div", "flex:1;min-width:0");
    yazi.appendChild(el("b", "", "⚠️ Kalkan: bu sayfa şüpheli. "));
    yazi.appendChild(el("span", "", (s.nedenler || [])[0] || "Bilgi girmeden önce adresi kontrol edin."));
    const kapat = el("button", "background:#d08a00;color:#fff;border:0;border-radius:6px;padding:6px 12px;cursor:pointer;font:13px sans-serif", "Tamam");
    kapat.onclick = () => host.remove();
    cubuk.append(yazi, kapat);
    kok.appendChild(cubuk);
  }

  tara();

  // Giriş formu sonradan yüklenirse (tek sayfa uygulamaları) bir kez daha tara
  let bekleme = null;
  const gozlemci = new MutationObserver(() => {
    if (gosterilen || taramaSayisi >= 3) return gozlemci.disconnect();
    if (!document.querySelector('input[type="password"]')) return;
    clearTimeout(bekleme);
    bekleme = setTimeout(tara, 800);
    gozlemci.disconnect();
  });
  if (document.body) gozlemci.observe(document.body, { childList: true, subtree: true });

  // Tek sayfa uygulamalarında adres değişimi
  let sonUrl = location.href;
  setInterval(() => {
    if (location.href !== sonUrl && !gosterilen) {
      sonUrl = location.href;
      taramaSayisi = 0; // her yeni adres için tarama hakkı sıfırlanır
      tara();
    }
  }, 2000);
})();
