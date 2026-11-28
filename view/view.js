// 자기앞엽서 PC 보기·인쇄. 서버 없음: 구글 드라이브 앱 전용 폴더에서 보기 묶음(jagiap-view.jgap)을 내려받아
// 브라우저 안에서 백업 비밀번호로 풀고(앱의 CryptoBox v2 와 같은 형식), 앱 「만들기」와 같은 인쇄 HTML 을 보여 준다.
"use strict";
(() => {
  const SCOPE = "https://www.googleapis.com/auth/drive.appdata";
  const API = "https://www.googleapis.com/drive/v3";
  const VIEW_NAME = "jagiap-view.jgap";
  const BASE = "https://jagiap.local/";
  const $ = (id) => document.getElementById(id);
  const msg = (t) => { $("msg").textContent = t || ""; };

  let token = null;
  let encrypted = null; // 내려받은 암호문 (ArrayBuffer)
  let urls = [];        // 만든 blob 주소 (닫을 때 정리)

  // ---- 1. 구글 로그인 (토큰만, 앱 전용 폴더 권한 하나) ------------------------------------
  let tokenClient = null;
  window.gisReady = () => {
    if (!window.JAGIAP_CLIENT_ID || window.JAGIAP_CLIENT_ID.startsWith("여기에")) {
      msg("아직 설정 중이에요 (구글 클라이언트 ID 가 없어요).");
      return;
    }
    tokenClient = google.accounts.oauth2.initTokenClient({
      client_id: window.JAGIAP_CLIENT_ID,
      scope: SCOPE,
      callback: async (r) => {
        if (r.error) { msg("구글 허락을 받지 못했어요."); return; }
        token = r.access_token;
        await fetchView();
      },
    });
  };
  $("login").onclick = () => {
    if (!tokenClient) { msg("구글 로그인을 불러오는 중이에요. 잠시 뒤 다시 눌러 주세요."); return; }
    tokenClient.requestAccessToken();
  };

  async function drive(path) {
    const r = await fetch(API + path, { headers: { Authorization: "Bearer " + token } });
    if (r.status === 401 || r.status === 403) throw new Error("구글 연결이 끊겼어요. 다시 들어가 주세요.");
    if (!r.ok) throw new Error("드라이브 응답 " + r.status);
    return r;
  }

  async function fetchView() {
    try {
      msg("드라이브에서 찾는 중이에요…");
      const q = "?spaces=appDataFolder&pageSize=100&orderBy=" + encodeURIComponent("modifiedTime desc") +
        "&fields=" + encodeURIComponent("files(id,name,size,modifiedTime)");
      const files = (await (await drive("/files" + q)).json()).files || [];
      const f = files.find((x) => x.name === VIEW_NAME);
      if (!f) { msg("드라이브에 보기 묶음이 없어요. 폰에서 「지금 백업하기」를 한 번 눌러 주세요."); return; }
      msg("내려받는 중이에요…");
      encrypted = await (await drive("/files/" + encodeURIComponent(f.id) + "?alt=media")).arrayBuffer();
      $("made").textContent = "(" + new Date(f.modifiedTime).toLocaleDateString("ko-KR") + " 백업)";
      $("step-login").hidden = true;
      $("step-pw").hidden = false;
      $("pw").focus();
      msg("");
    } catch (e) { msg(e.message); }
  }

  // ---- 2. 암호 풀기 (PBKDF2-HMAC-SHA256 → AES-256-GCM 조각, 앱과 같은 v2 형식) -------------
  async function deriveKey(pwBytes, salt, iterations) {
    const base = await crypto.subtle.importKey("raw", pwBytes, "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, base,
      { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  }

  async function decrypt(buf, pwBytes) {
    const u8 = new Uint8Array(buf);
    const dv = new DataView(buf);
    if (String.fromCharCode(u8[0], u8[1], u8[2], u8[3]) !== "JGAP" || u8[4] !== 2) throw new Error("자기앞엽서 파일이 아니에요");
    const iterations = dv.getInt32(5);
    const salt = u8.slice(9, 25);
    const prefix = u8.slice(25, 33);
    const header = u8.slice(0, 33);
    const key = await deriveKey(pwBytes, salt, iterations);
    const parts = [];
    let p = 33, index = 0, total = 0, last = false;
    while (!last) {
      if (p + 5 > u8.length) throw new Error("파일이 잘렸어요");
      const flag = u8[p];
      const n = dv.getInt32(p + 1);
      const enc = u8.subarray(p + 5, p + 5 + n);
      p += 5 + n;
      const iv = new Uint8Array(12); iv.set(prefix); new DataView(iv.buffer).setInt32(8, index);
      const aad = new Uint8Array(header.length + 5); aad.set(header);
      new DataView(aad.buffer).setInt32(header.length, index); aad[header.length + 4] = flag;
      const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, key, enc));
      parts.push(plain); total += plain.length; index++;
      last = flag === 1;
    }
    if (p !== u8.length) throw new Error("파일이 손상됐어요");
    const out = new Uint8Array(total);
    let o = 0; for (const x of parts) { out.set(x, o); o += x.length; }
    return out;
  }

  // 비밀번호 바이트: UTF-8 이 기본. 예전 안드로이드 방식(글자마다 아래 8비트)도 한 번 더 시도한다
  function pwVariants(pw) {
    const utf8 = new TextEncoder().encode(pw);
    const low = new Uint8Array([...pw].flatMap((ch) => { const c = ch.charCodeAt(0); return ch.length === 2 ? [ch.charCodeAt(0) & 255, ch.charCodeAt(1) & 255] : [c & 255]; }));
    return [utf8, low].filter((v, i, a) => i === 0 || v.join() !== a[0].join());
  }

  // ---- 3. zip 풀기 (가운데 목차 기준, 압축은 브라우저의 deflate-raw) -----------------------
  async function unzip(u8) {
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    let e = u8.length - 22;
    while (e >= 0 && dv.getUint32(e, true) !== 0x06054b50) e--;
    if (e < 0) throw new Error("묶음이 손상됐어요");
    const count = dv.getUint16(e + 10, true);
    let p = dv.getUint32(e + 16, true);
    const files = new Map();
    for (let i = 0; i < count; i++) {
      if (dv.getUint32(p, true) !== 0x02014b50) throw new Error("묶음이 손상됐어요");
      const method = dv.getUint16(p + 10, true);
      const size = dv.getUint32(p + 20, true);
      const nameLen = dv.getUint16(p + 28, true), extraLen = dv.getUint16(p + 30, true), commentLen = dv.getUint16(p + 32, true);
      const local = dv.getUint32(p + 42, true);
      const name = new TextDecoder().decode(u8.subarray(p + 46, p + 46 + nameLen));
      p += 46 + nameLen + extraLen + commentLen;
      const start = local + 30 + dv.getUint16(local + 26, true) + dv.getUint16(local + 28, true);
      const raw = u8.subarray(start, start + size);
      let data;
      if (method === 0) data = raw.slice();
      else if (method === 8) data = new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(new DecompressionStream("deflate-raw"))).arrayBuffer());
      else throw new Error("읽을 수 없는 묶음이에요");
      if (name.includes("..") || name.startsWith("/")) continue;
      files.set(name, data);
    }
    return files;
  }

  const MIME = { ttf: "font/ttf", otf: "font/otf", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", webp: "image/webp" };

  $("pw-form").onsubmit = async (ev) => {
    ev.preventDefault();
    const pw = $("pw").value;
    if (!pw || !encrypted) return;
    msg("푸는 중이에요…");
    let plain = null;
    for (const bytes of pwVariants(pw)) {
      try { plain = await decrypt(encrypted, bytes); break; } catch (_) { /* 다음 방식 */ }
    }
    $("pw").value = "";
    if (!plain) { msg("비밀번호가 틀렸거나 파일이 손상됐어요."); return; }
    try {
      const files = await unzip(plain);
      plain = null;
      show(files);
      msg("");
    } catch (e) { msg(e.message); }
  };

  // ---- 4. 보여 주기·인쇄 -------------------------------------------------------------------
  function show(files) {
    urls.forEach(URL.revokeObjectURL); urls = [];
    const assets = {};
    for (const [name, data] of files) {
      if (name === "index.json" || name.startsWith("pages/")) continue;
      const ext = name.split(".").pop().toLowerCase();
      const u = URL.createObjectURL(new Blob([data], { type: MIME[ext] || "application/octet-stream" }));
      urls.push(u); assets[name] = u;
    }
    const index = JSON.parse(new TextDecoder().decode(files.get("index.json")));
    const nav = $("pages"); nav.textContent = "";
    const groups = { calendar: "우표 달력", book: "엽서 책자" };
    let first = null;
    for (const kind of Object.keys(groups)) {
      const list = index.pages.filter((p) => p.kind === kind);
      if (!list.length) continue;
      const h = document.createElement("h3"); h.textContent = groups[kind]; nav.appendChild(h);
      for (const p of list) {
        const a = document.createElement("a");
        a.textContent = p.title;
        a.onclick = () => open(p, a);
        nav.appendChild(a);
        first = first || [p, a];
      }
    }
    function open(p, a) {
      nav.querySelectorAll("a").forEach((x) => x.classList.toggle("on", x === a));
      $("title").textContent = p.title;
      const html = new TextDecoder().decode(files.get(p.file))
        .replace(/https:\/\/jagiap\.local\/([^'")\s]+)/g, (m, path) => assets[path] || "");
      $("frame").srcdoc = html;
    }
    $("step-pw").hidden = true;
    $("step-view").hidden = false;
    if (first) open(first[0], first[1]);
  }

  $("print").onclick = () => {
    const w = $("frame").contentWindow;
    if (w) { w.focus(); w.print(); }
  };

  window.addEventListener("pagehide", () => { urls.forEach(URL.revokeObjectURL); urls = []; encrypted = null; });
})();
