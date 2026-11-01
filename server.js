require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be at least 32 characters");
}

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is missing");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DB_SSL === "true"
    ? { rejectUnauthorized: false }
    : undefined
});

const PLANS = {
  basic: {
    name: "Basic",
    price: 5,
    features: ["1 landing page", "Basic analytics", "WhatsApp button"]
  },
  prime: {
    name: "Prime & Pro",
    price: 12,
    features: ["5 landing pages", "Visitor analytics", "Meta Pixel option"]
  },
  combo: {
    name: "Basic & Prime",
    price: 15,
    features: ["10 landing pages", "Analytics", "WhatsApp leads"]
  }
};

const RECEIVE_ADDRESS =
  process.env.TRON_RECEIVE_ADDRESS ||
  "TVFeDBy2GFPNB5JJgNpRF8otsFcRVPb4ak";

const USDT_CONTRACT_HEX =
  "41a614f803b6fd780986a42c78ec9c7f77e6ded13c";

const TRANSFER_TOPIC =
  "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({ limit: "1mb" }));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: true,
  legacyHeaders: false
}));

app.use(express.static(path.join(__dirname, "public")));

function normalizeAddress(address) {
  return String(address || "").replace(/^0x/i, "").toLowerCase();
}

function tronAddressHex(address) {
  try {
    if (/^T/.test(address)) {
      const alphabet =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

      let num = 0n;

      for (const char of address) {
        const index = alphabet.indexOf(char);
        if (index < 0) return null;
        num = num * 58n + BigInt(index);
      }

      let hex = num.toString(16);
      if (hex.length % 2) hex = "0" + hex;

      const bytes = Buffer.from(hex, "hex");
      const payload = bytes.subarray(0, -4);

      return payload.toString("hex").toLowerCase();
    }

    return normalizeAddress(address);
  } catch {
    return null;
  }
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      plan TEXT,
      subscription_until TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS pages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      headline TEXT,
      description TEXT,
      image_url TEXT,
      whatsapp_number TEXT,
      button_text TEXT,
      pixel_id TEXT,
      slug TEXT UNIQUE NOT NULL,
      published BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      plan TEXT NOT NULL,
      amount NUMERIC(18,6) NOT NULL,
      txid TEXT UNIQUE NOT NULL,
      status TEXT DEFAULT 'verified',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY,
      page_id INTEGER REFERENCES pages(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL,
      suspicious BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;

  if (email && password) {
    const existing = await pool.query(
      "SELECT id FROM users WHERE email=$1",
      [email.toLowerCase()]
    );

    if (!existing.rowCount) {
      const hash = await bcrypt.hash(password, 12);

      await pool.query(
        `INSERT INTO users(name,email,password,role)
         VALUES($1,$2,$3,'admin')`,
        ["Administrator", email.toLowerCase(), hash]
      );
    }
  }

  console.log("Database initialized");
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({ error: "Please login first" });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired login" });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

function slugify(text) {
  const slug = String(text || "page")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 45);

  return slug || crypto.randomBytes(5).toString("hex");
}

app.get("/api/config", (req, res) => {
  res.json({
    plans: PLANS,
    receiveAddress: RECEIVE_ADDRESS,
    network: "TRC20"
  });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password || password.length < 10) {
      return res.status(400).json({
        error: "Name, valid email and password of at least 10 characters required"
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users(name,email,password)
       VALUES($1,$2,$3)
       RETURNING id,name,email,role`,
      [name.trim(), email.toLowerCase().trim(), hash]
    );

    const user = result.rows[0];

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, user });
  } catch (error) {
    res.status(400).json({
      error: error.code === "23505"
        ? "Email already registered"
        : "Registration failed"
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [String(email || "").toLowerCase().trim()]
    );

    if (!result.rowCount) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password || "", user.password);

    if (!valid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch {
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/me", auth, async (req, res) => {
  const result = await pool.query(
    `SELECT id,name,email,role,plan,subscription_until
     FROM users WHERE id=$1`,
    [req.user.id]
  );

  if (!result.rowCount) {
    return res.status(404).json({ error: "User not found" });
  }

  res.json({ user: result.rows[0] });
});

app.post("/api/pages", auth, async (req, res) => {
  try {
    const {
      title,
      headline,
      description,
      imageUrl,
      whatsappNumber,
      buttonText,
      pixelId
    } = req.body;

    if (!title || !headline) {
      return res.status(400).json({
        error: "Page title and headline are required"
      });
    }

    const user = await pool.query(
      "SELECT plan,subscription_until FROM users WHERE id=$1",
      [req.user.id]
    );

    const subscription = user.rows[0];

    if (
      !subscription.plan ||
      !subscription.subscription_until ||
      new Date(subscription.subscription_until) < new Date()
    ) {
      return res.status(403).json({
        error: "Please activate a monthly plan first"
      });
    }

    const slug =
      slugify(title) + "-" + crypto.randomBytes(3).toString("hex");

    const result = await pool.query(
      `INSERT INTO pages
       (user_id,title,headline,description,image_url,
        whatsapp_number,button_text,pixel_id,slug)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING *`,
      [
        req.user.id,
        title,
        headline,
        description || "",
        imageUrl || "",
        whatsappNumber || "",
        buttonText || "Contact on WhatsApp",
        pixelId || "",
        slug
      ]
    );

    res.json({ page: result.rows[0] });
  } catch {
    res.status(500).json({ error: "Could not create page" });
  }
});

app.get("/api/pages", auth, async (req, res) => {
  const result = await pool.query(
    `SELECT * FROM pages
     WHERE user_id=$1 ORDER BY created_at DESC`,
    [req.user.id]
  );

  res.json(result.rows);
});

app.post("/api/pages/:id/publish", auth, async (req, res) => {
  const result = await pool.query(
    `UPDATE pages SET published=TRUE
     WHERE id=$1 AND user_id=$2 RETURNING slug`,
    [req.params.id, req.user.id]
  );

  if (!result.rowCount) {
    return res.status(404).json({ error: "Page not found" });
  }

  res.json({ url: "/p/" + result.rows[0].slug });
});

app.get("/p/:slug", async (req, res) => {
  const result = await pool.query(
    `SELECT * FROM pages
     WHERE slug=$1 AND published=TRUE`,
    [req.params.slug]
  );

  if (!result.rowCount) {
    return res.status(404).send("Page not found");
  }

  const p = result.rows[0];

  await pool.query(
    `INSERT INTO events(page_id,event_type,suspicious)
     VALUES($1,'visit',FALSE)`,
    [p.id]
  );

  const safe = value => String(value || "")
    .replace(/[&<>"']/g, char => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    })[char]);

  const image = /^https:\/\//i.test(p.image_url || "")
    ? `<img src="${safe(p.image_url)}" style="max-width:100%;border-radius:15px">`
    : "";

  const pixel = /^\d+$/.test(p.pixel_id || "")
    ? `<script>!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};n.queue=[];t=b.createElement(e);t.async=true;t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');fbq('init','${safe(p.pixel_id)}');fbq('track','PageView');</script>`
    : "";

  const phone = String(p.whatsapp_number || "").replace(/\D/g, "");
  const whatsapp = phone
    ? `<a href="https://wa.me/${phone}" onclick="fetch('/api/events/${p.id}/click',{method:'POST'})" style="display:inline-block;background:#16a34a;color:white;padding:15px 25px;border-radius:10px;text-decoration:none;font-weight:bold">${safe(p.button_text)}</a>`
    : "";

  res.send(`<!doctype html>
  <html><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${safe(p.title)}</title>${pixel}
  <style>
  body{margin:0;background:#081426;color:white;font-family:Arial;text-align:center}
  main{max-width:650px;margin:50px auto;padding:25px}
  p{line-height:1.7;color:#cbd5e1}
  </style></head>
  <body><main>
  <h1>${safe(p.headline)}</h1>
  ${image}<p>${safe(p.description)}</p>${whatsapp}
  </main></body></html>`);
});

app.post("/api/events/:id/:type", async (req, res) => {
  const type = ["lead", "click"].includes(req.params.type)
    ? req.params.type
    : null;

  if (!type) return res.status(400).json({ error: "Invalid event" });

  const page = await pool.query(
    "SELECT id FROM pages WHERE id=$1 AND published=TRUE",
    [req.params.id]
  );

  if (!page.rowCount) return res.status(404).json({ error: "Page not found" });

  const ua = String(req.headers["user-agent"] || "").toLowerCase();
  const suspicious =
    !ua ||
    /bot|crawler|spider|headless|curl|python|wget/.test(ua);

  await pool.query(
    `INSERT INTO events(page_id,event_type,suspicious)
     VALUES($1,$2,$3)`,
    [req.params.id, type, suspicious]
  );

  res.json({ ok: true });
});

app.get("/api/analytics", auth, async (req, res) => {
  const result = await pool.query(
    `SELECT p.id,p.title,
      COUNT(e.id) FILTER(WHERE e.event_type='visit') AS visits,
      COUNT(e.id) FILTER(WHERE e.event_type='lead') AS leads,
      COUNT(e.id) FILTER(WHERE e.event_type='click') AS clicks,
      COUNT(e.id) FILTER(WHERE e.suspicious=TRUE) AS suspicious,
      COUNT(e.id) AS events
     FROM pages p
     LEFT JOIN events e ON e.page_id=p.id
     WHERE p.user_id=$1
     GROUP BY p.id ORDER BY p.id DESC`,
    [req.user.id]
  );

  res.json(result.rows);
});

async function verifyTronPayment(txid, expectedAmount) {
  const apiKey = process.env.TRONGRID_API_KEY;
  const endpoint =
    "https://api.trongrid.io/v1/transactions/" +
    encodeURIComponent(txid) +
    "/events";

  const response = await fetch(endpoint, {
    headers: apiKey ? { "TRON-PRO-API-KEY": apiKey } : {}
  });

  if (!response.ok) {
    throw new Error("Could not check transaction on TRON network");
  }

  const data = await response.json();

  const expectedReceiver = tronAddressHex(RECEIVE_ADDRESS);

  for (const event of data.data || []) {
    const contract = normalizeAddress(event.contract_address);
    const eventName = event.event_name;
    const result = event.result || {};

    const contractMatch =
      contract === normalizeAddress(USDT_CONTRACT_HEX) ||
      contract === normalizeAddress(USDT_CONTRACT_HEX.slice(2));

    if (!contractMatch || eventName !== "Transfer") continue;

    const receiver = normalizeAddress(result.to);
    const receiverMatch =
      receiver === expectedReceiver ||
      receiver === expectedReceiver?.slice(2);

    if (!receiverMatch) continue;

    const amount = Number(result.value) / 1_000_000;

    if (amount === expectedAmount) {
      return true;
    }
  }

  return false;
}

app.post("/api/payments/verify", auth, async (req, res) => {
  try {
    const { plan, txid } = req.body;

    if (!PLANS[plan]) {
      return res.status(400).json({ error: "Invalid plan" });
    }

    if (!/^[a-fA-F0-9]{64}$/.test(txid || "")) {
      return res.status(400).json({ error: "Invalid transaction ID" });
    }

    const existing = await pool.query(
      "SELECT id FROM payments WHERE txid=$1",
      [txid]
    );

    if (existing.rowCount) {
      return res.status(409).json({
        error: "This transaction ID has already been used"
      });
    }

    const confirmed = await verifyTronPayment(txid, PLANS[plan].price);

    if (!confirmed) {
      return res.status(400).json({
        error: "Payment not found. Check network, amount and confirmation."
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const duplicate = await client.query(
        "SELECT id FROM payments WHERE txid=$1 FOR UPDATE",
        [txid]
      );

      if (duplicate.rowCount) {
        throw new Error("Transaction already used");
      }

      await client.query(
        `INSERT INTO payments(user_id,plan,amount,txid,status)
         VALUES($1,$2,$3,$4,'verified')`,
        [req.user.id, plan, PLANS[plan].price, txid]
      );

      await client.query(
        `UPDATE users
         SET plan=$1,
             subscription_until=GREATEST(
               COALESCE(subscription_until,NOW()),NOW()
             ) + INTERVAL '30 days'
         WHERE id=$2`,
        [plan, req.user.id]
      );

      await client.query("COMMIT");

      res.json({
        ok: true,
        message: "Payment verified. Subscription activated for 30 days.",
        amount: PLANS[plan].price
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    res.status(400).json({ error: error.message || "Payment verification failed" });
  }
});

app.get("/api/admin/overview", auth, adminOnly, async (req, res) => {
  const result = await pool.query(`
    SELECT
      (SELECT COUNT(*) FROM users WHERE role='user') AS users,
      (SELECT COUNT(*) FROM pages) AS pages,
      (SELECT COUNT(*) FROM payments WHERE status='verified') AS payments,
      (SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='verified') AS usdt,
      (SELECT COUNT(*) FROM events) AS events,
      (SELECT COUNT(*) FROM events WHERE suspicious=TRUE) AS suspicious
  `);

  res.json(result.rows[0]);
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`ADS GROWTH AGENCY PRO running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Startup failed:", error);
    process.exit(1);
  });
