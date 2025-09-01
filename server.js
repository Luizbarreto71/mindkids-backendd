import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { createClient } from '@supabase/supabase-js';
import mercadopago from 'mercadopago';

const app = express();
const PORT = process.env.PORT || 8080;

// 🔑 Variáveis de ambiente
const JWT_SECRET = process.env.JWT_SECRET;
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || '*';
const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

// 🚀 Supabase client
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// 🚀 Mercado Pago
mercadopago.configure({
  access_token: MP_ACCESS_TOKEN
});

// Middlewares
app.use(cors({ origin: CLIENT_ORIGIN, credentials: true }));
app.use(express.json());

// JWT Helper
function createToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, is_paid: !!user.is_paid },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// Auth Middleware
function authRequired(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = auth.slice(7);

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function paidRequired(req, res, next) {
  if (!req.user?.is_paid) return res.status(402).json({ error: 'Payment required' });
  next();
}

// ------------------ AUTH ------------------

// Register
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const passwordHash = bcrypt.hashSync(password, 10);

  const { data, error } = await supabase
    .from('users')
    .insert([{ email, password_hash: passwordHash, is_paid: false }])
    .select()
    .single();

  if (error) {
    if (String(error.message).includes('duplicate')) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    return res.status(500).json({ error: 'Database error', details: error.message });
  }

  const user = { id: data.id, email: data.email, is_paid: data.is_paid };
  const token = createToken(user);

  return res.json({ token, user });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single();

  if (error || !user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = bcrypt.compareSync(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const token = createToken(user);
  return res.json({ token, user });
});

// Me
app.get('/api/auth/me', authRequired, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('id, email, is_paid, created_at')
    .eq('id', req.user.id)
    .single();

  if (error) return res.status(500).json({ error: 'Database error' });
  return res.json({ user: data });
});

// ------------------ PAGAMENTO ------------------

// Criar pagamento
app.post('/api/pay/create', authRequired, async (req, res) => {
  const { title = 'Assinatura Premium', price = 9.9, quantity = 1, currency_id = 'BRL' } = req.body;

  const preference = {
    items: [{ title, unit_price: Number(price), quantity: Number(quantity), currency_id }],
    back_urls: {
      success: process.env.MP_SUCCESS_URL || 'https://example.com/success',
      failure: process.env.MP_FAILURE_URL || 'https://example.com/failure',
      pending: process.env.MP_PENDING_URL || 'https://example.com/pending'
    },
    auto_return: 'approved',
    metadata: { userId: req.user.id }
  };

  try {
    const result = await mercadopago.preferences.create(preference);
    return res.json({ init_point: result.body.init_point, id: result.body.id });
  } catch (e) {
    return res.status(500).json({ error: 'Mercado Pago error', details: e.message });
  }
});

// Webhook
app.post('/api/pay/webhook', async (req, res) => {
  const { type, data } = req.body || {};

  if (type === 'payment' && data?.id) {
    try {
      const payment = await mercadopago.payment.findById(data.id);
      const status = payment.body.status;
      const amount = payment.body.transaction_amount;
      const userId = payment.body.metadata?.userId;

      if (userId) {
        await supabase.from('payments').insert([
          {
            user_id: userId,
            mp_payment_id: String(data.id),
            status,
            amount,
            raw: payment.body
          }
        ]);

        if (status === 'approved') {
          await supabase.from('users').update({ is_paid: true }).eq('id', userId);
        }
      }
    } catch (err) {
      console.error('Webhook error:', err.message);
    }
  }

  res.sendStatus(200);
});

// Protected route
app.get('/api/pro/feature', authRequired, paidRequired, (req, res) => {
  res.json({ ok: true, message: 'Conteúdo premium liberado.' });
});

// Health check
app.get('/api/health', (req, res) => res.json({ ok: true }));

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Backend running at http://0.0.0.0:${PORT}`);
});
