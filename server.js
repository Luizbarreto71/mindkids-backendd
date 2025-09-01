import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import pkg from "pg";
import { MercadoPagoConfig, Preference } from "mercadopago";

dotenv.config();

const { Pool } = pkg;
const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "change_me_in_prod";
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || "*";

// CORS e JSON
app.use(cors({ origin: CLIENT_ORIGIN, credentials: true }));
app.use(express.json());

// PostgreSQL (Supabase usa Postgres)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Mercado Pago SDK
const client = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN
});

// 🔹 Funções utilitárias
function createToken(user) {
  return jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });
}

function authRequired(req, res, next) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) return res.status(401).json({ error: "Unauthorized" });
  const token = auth.slice(7);
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function paidRequired(req, res, next) {
  if (!req.user?.is_paid) return res.status(402).json({ error: "Payment required" });
  next();
}

// 🔹 Rotas de autenticação
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });

  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = await pool.query(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, is_paid",
      [email, hash]
    );
    const user = result.rows[0];
    const token = createToken(user);
    res.json({ token, user });
  } catch (err) {
    if (String(err.message).includes("duplicate")) {
      return res.status(409).json({ error: "Email already registered" });
    }
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    const token = createToken(user);
    res.json({ token, user });
  } catch {
    res.status(500).json({ error: "Database error" });
  }
});

// 🔹 Criar pagamento Mercado Pago
app.post("/api/pay/create", authRequired, async (req, res) => {
  try {
    const preference = await new Preference(client).create({
      items: [
        {
          title: "Assinatura - MindKids",
          quantity: 1,
          unit_price: 19.9,
          currency_id: "BRL"
        }
      ],
      back_urls: {
        success: process.env.MP_SUCCESS_URL || "https://example.com/success",
        failure: process.env.MP_FAILURE_URL || "https://example.com/failure",
        pending: process.env.MP_PENDING_URL || "https://example.com/pending"
      },
      auto_return: "approved",
      metadata: { userId: req.user.id }
    });

    res.json({ init_point: preference.init_point });
  } catch (e) {
    console.error("❌ Erro Mercado Pago:", e);
    res.status(500).json({ error: "Erro ao criar pagamento" });
  }
});

// 🔹 Webhook Mercado Pago
app.post("/api/pay/webhook", async (req, res) => {
  console.log("📩 Webhook recebido:", req.body);
  res.sendStatus(200);
});

// Rota protegida exemplo
app.get("/api/pro/feature", authRequired, paidRequired, (req, res) => {
  res.json({ ok: true, message: "Conteúdo premium liberado." });
});

app.get("/api/health", (req, res) => res.json({ ok: true }));

// 🔹 Inicia servidor
app.listen(PORT, () => {
  console.log(`🚀 Backend rodando em http://0.0.0.0:${PORT}`);
});
