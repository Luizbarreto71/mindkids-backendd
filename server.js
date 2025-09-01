import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { createClient } from "@supabase/supabase-js";
import mercadopago from "mercadopago";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change_me";
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || "*";

// === MIDDLEWARES ===
app.use(cors({ origin: CLIENT_ORIGIN, credentials: true }));
app.use(express.json());

// === SUPABASE CONFIG ===
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// === MERCADO PAGO CONFIG ===
mercadopago.configure({
  access_token: process.env.MP_ACCESS_TOKEN
});

// === FUNÇÕES AUXILIARES ===
function createToken(user) {
  return jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });
}

function authRequired(req, res, next) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) return res.status(401).json({ error: "Unauthorized" });
  try {
    const token = auth.slice(7);
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// === ROTAS DE AUTENTICAÇÃO ===
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });

  const passwordHash = bcrypt.hashSync(password, 10);

  const { data, error } = await supabase
    .from("users")
    .insert([{ email, password_hash: passwordHash, is_paid: false }])
    .select()
    .single();

  if (error) {
    if (error.code === "23505") return res.status(409).json({ error: "Email already registered" });
    return res.status(500).json({ error: "Database error" });
  }

  const token = createToken({ id: data.id, email: data.email, is_paid: data.is_paid });
  res.json({ token, user: data });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });

  const { data: user, error } = await supabase
    .from("users")
    .select("*")
    .eq("email", email)
    .single();

  if (error || !user) return res.status(401).json({ error: "Invalid credentials" });

  const valid = bcrypt.compareSync(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: "Invalid credentials" });

  const token = createToken({ id: user.id, email: user.email, is_paid: user.is_paid });
  res.json({ token, user });
});

app.get("/api/auth/me", authRequired, async (req, res) => {
  const { data, error } = await supabase
    .from("users")
    .select("id, email, is_paid, created_at")
    .eq("id", req.user.id)
    .single();

  if (error) return res.status(500).json({ error: "Database error" });
  res.json({ user: data });
});

// === MERCADO PAGO ===
app.post("/api/pay/create", authRequired, async (req, res) => {
  const { title = "Plano Premium", price = 19.9, quantity = 1, currency_id = "BRL" } = req.body || {};
  const preference = {
    items: [{ title, unit_price: Number(price), quantity: Number(quantity), currency_id }],
    back_urls: {
      success: process.env.MP_SUCCESS_URL || "https://example.com/success",
      failure: process.env.MP_FAILURE_URL || "https://example.com/failure",
      pending: process.env.MP_PENDING_URL || "https://example.com/pending"
    },
    auto_return: "approved",
    metadata: { userId: req.user.id }
  };

  try {
    const result = await mercadopago.preferences.create(preference);
    return res.json({ init_point: result.body.init_point, id: result.body.id });
  } catch (e) {
    return res.status(500).json({ error: "Mercado Pago error" });
  }
});

app.post("/api/pay/webhook", express.json(), async (req, res) => {
  const { type, data } = req.body || {};
  if (type === "payment" && data?.id) {
    try {
      const payment = await mercadopago.payment.findById(data.id);
      const status = payment.body.status;
      const userId = payment.body.metadata?.userId;

      if (userId) {
        await supabase.from("payments").insert([
          {
            user_id: userId,
            mp_payment_id: String(data.id),
            status,
            amount: payment.body.transaction_amount,
            raw: payment.body
          }
        ]);

        if (status === "approved") {
          await supabase.from("users").update({ is_paid: true }).eq("id", userId);
        }
      }
    } catch {}
  }
  res.sendStatus(200);
});

// === HEALTHCHECK ===
app.get("/api/health", (req, res) => res.json({ ok: true }));

// === START SERVER (Vercel ignora essa porta, mas roda localmente) ===
app.listen(PORT, () => {
  console.log(`🚀 Backend listening on http://localhost:${PORT}`);
});
