// Vercel serverless function. No npm packages needed (Node 18+).
const crypto = require("crypto");
const clean = v => String(v || "").trim();
const SUPABASE_URL = clean(process.env.SUPABASE_URL).replace(/\/+$/, "").replace(/\/rest\/v1$/, "");
const KEY = clean(process.env.SUPABASE_SERVICE_KEY), SECRET = clean(process.env.AUTH_SECRET);
const enc = encodeURIComponent;

async function sb(path, method = "GET", body) {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    method,
    headers: { apikey: KEY, Authorization: `Bearer ${KEY}`, "Content-Type": "application/json", Prefer: "return=representation" },
    body: body ? JSON.stringify(body) : undefined
  });
  const t = await r.text();
  if (!r.ok) throw new Error(t);
  return t ? JSON.parse(t) : [];
}

/* Passwords: scrypt hash. Sessions: HMAC-signed token valid for 30 days. */
const hash = (pw, salt = crypto.randomBytes(16).toString("hex")) => salt + ":" + crypto.scryptSync(pw, salt, 32).toString("hex");
const same = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const mac = b => crypto.createHmac("sha256", SECRET).update(b).digest("base64url");
const sign = p => { const b = Buffer.from(JSON.stringify(p)).toString("base64url"); return b + "." + mac(b); };
function verify(t) {
  const [b, s] = (t || "").split(".");
  if (!b || !s || !same(s, mac(b))) return null;
  const p = JSON.parse(Buffer.from(b, "base64url").toString());
  return p.exp > Date.now() ? p : null;
}
const session = (u, dealerId) => {
  const user = { id: u.id, name: u.name, phone: u.phone, role: u.role, dealerId };
  return { token: sign({ ...user, exp: Date.now() + 30 * 864e5 }), user };
};

module.exports = async (req, res) => {
  const say = (c, o) => res.status(c).json(o);
  if (req.method === "GET") { // health check: open /api/rpc in a browser. Shows no secrets.
    let keyType = "missing";
    if (KEY) { try { keyType = JSON.parse(Buffer.from(KEY.split(".")[1], "base64url")).role; } catch { keyType = KEY.startsWith("sb_secret_") ? "service_role (new format)" : KEY.startsWith("sb_publishable_") ? "anon - WRONG KEY" : "unknown format"; } }
    let db = "not tested";
    if (SUPABASE_URL && KEY) { try { await sb("users?select=id&limit=1"); db = "ok"; } catch (e) { db = "failed: " + String(e.message).slice(0, 250); } }
    return say(200, { SUPABASE_URL_set: !!SUPABASE_URL, SUPABASE_URL_looks_right: /^https:\/\/[a-z0-9-]+\.supabase\.co$/.test(SUPABASE_URL), SUPABASE_SERVICE_KEY_set: !!KEY, key_type: keyType, AUTH_SECRET_set: !!SECRET, database: db });
  }
  if (req.method !== "POST") return say(405, { error: "POST only" });
  if (!SUPABASE_URL || !KEY || !SECRET) return say(500, { error: "Server is not configured yet." });
  const b = req.body || {};
  try {
    if (b.action === "register") {
      const phone = String(b.phone || "").replace(/\s/g, ""), name = String(b.name || "").trim().slice(0, 60);
      const role = b.role === "seller" ? "seller" : "buyer", shop = String(b.shop || "").trim().slice(0, 80);
      if (!/^\+?\d{9,13}$/.test(phone) || name.length < 2 || String(b.password || "").length < 6) return say(400, { error: "Check your name, phone number and password (6+ characters)." });
      if (role === "seller" && shop.length < 2) return say(400, { error: "Enter your shop name." });
      if ((await sb(`users?phone=eq.${enc(phone)}&select=id`)).length) return say(409, { error: "That phone number already has an account. Log in instead." });
      const [u] = await sb("users", "POST", { name, phone, role, pass_hash: hash(String(b.password)) });
      let dealerId = null;
      if (role === "seller") {
        const [d] = await sb("dealers", "POST", { owner_id: u.id, name: shop, location: String(b.location || "Abossey Okai").slice(0, 100), phone });
        dealerId = d.id;
      }
      return say(200, session(u, dealerId));
    }
    if (b.action === "login") {
      const [u] = await sb(`users?phone=eq.${enc(String(b.phone || "").replace(/\s/g, ""))}&select=*`);
      if (!u || !same(hash(String(b.password || ""), u.pass_hash.split(":")[0]), u.pass_hash)) return say(401, { error: "Wrong phone number or password." });
      let dealerId = null;
      if (u.role === "seller") dealerId = ((await sb(`dealers?owner_id=eq.${u.id}&select=id`))[0] || {}).id;
      return say(200, session(u, dealerId));
    }

    const me = verify((req.headers.authorization || "").replace("Bearer ", ""));
    if (!me) return say(401, { error: "Please log in again." });
    const seller = me.role === "seller" && me.dealerId;

    if (b.action === "sync") {
      const ds = await sb("dealers?select=id,name,location,phone,parts(id,name,brand,price,stock,img)&order=created_at.desc");
      const os = await sb(`orders?${seller ? `dealer_id=eq.${me.dealerId}` : `buyer_id=eq.${me.id}`}&order=created_at.desc&select=*`);
      return say(200, {
        dealers: ds.map(d => ({ ...d, parts: (d.parts || []).map(p => ({ ...p, price: Number(p.price) })) })),
        orders: os.map(o => ({ id: o.id, dealerId: o.dealer_id, buyerName: o.buyer_name, buyerPhone: o.buyer_phone, part: o.part_name, qty: o.qty, total: Number(o.total), mode: o.mode, address: o.address, status: o.status, rider: o.rider, at: Date.parse(o.created_at) }))
      });
    }

    if (b.action === "placeOrder") {
      if (me.role !== "buyer") return say(403, { error: "Only buyers can place orders." });
      const [p] = await sb(`parts?id=eq.${enc(b.partId)}&select=id,name,price,stock,dealer_id`);
      const qty = parseInt(b.qty, 10), delivery = b.mode === "delivery", address = String(b.address || "").trim().slice(0, 200);
      if (!p) return say(404, { error: "That part is no longer listed." });
      if (!(qty >= 1 && qty <= p.stock)) return say(409, { error: `Only ${p.stock} left in stock.` });
      if (delivery && address.length < 4) return say(400, { error: "Enter a delivery address." });
      const upd = await sb(`parts?id=eq.${p.id}&stock=eq.${p.stock}`, "PATCH", { stock: p.stock - qty });
      if (!upd.length) return say(409, { error: "Stock just changed. Please try again." });
      await sb("orders", "POST", { dealer_id: p.dealer_id, buyer_id: me.id, buyer_name: me.name, buyer_phone: me.phone, part_name: p.name, qty, total: qty * Number(p.price), mode: delivery ? "delivery" : "pickup", address: delivery ? address : "" });
      return say(200, { ok: true });
    }

    if (!seller) return say(403, { error: "Only sellers can do that." });
    const mine = `dealer_id=eq.${me.dealerId}`;
    const img = typeof b.img === "string" && b.img.startsWith("data:image/jpeg;base64,") && b.img.length < 200000 ? b.img : null;

    if (b.action === "addPart") {
      const price = parseFloat(b.price), stock = parseInt(b.stock, 10), name = String(b.name || "").trim().slice(0, 100);
      if (!name || !(price >= 0) || !(stock >= 0)) return say(400, { error: "Enter the part name, price and quantity." });
      await sb("parts", "POST", { dealer_id: me.dealerId, name, brand: String(b.brand || "").slice(0, 100), price, stock, img });
      return say(200, { ok: true });
    }
    if (b.action === "updatePart") {
      const patch = {};
      if (b.price !== undefined && parseFloat(b.price) >= 0) patch.price = parseFloat(b.price);
      if (b.stock !== undefined && parseInt(b.stock, 10) >= 0) patch.stock = parseInt(b.stock, 10);
      if (img) patch.img = img;
      if (!Object.keys(patch).length) return say(400, { error: "Nothing to update." });
      await sb(`parts?id=eq.${enc(b.id)}&${mine}`, "PATCH", patch);
      return say(200, { ok: true });
    }
    if (b.action === "deletePart") {
      await sb(`parts?id=eq.${enc(b.id)}&${mine}`, "DELETE");
      return say(200, { ok: true });
    }
    if (b.action === "advance") {
      const [o] = await sb(`orders?id=eq.${enc(b.id)}&${mine}&select=id,status,mode`);
      if (!o || o.status >= 3) return say(400, { error: "This order is already complete." });
      const patch = { status: o.status + 1 };
      if (o.mode === "delivery" && o.status === 1) patch.rider = String(b.rider || "").trim().slice(0, 100);
      await sb(`orders?id=eq.${o.id}&status=eq.${o.status}`, "PATCH", patch);
      return say(200, { ok: true });
    }
    return say(400, { error: "Unknown action." });
  } catch (e) {
    console.error(e);
    return say(500, { error: "Server error. Please try again." });
  }
};

