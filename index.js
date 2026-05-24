require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const { types } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// 起動時クラッシュを防ぐため遅延初期化
let _stripe = null;
function getStripe() {
  if (!_stripe) {
    const key = process.env.STRIPE_SECRET_KEY;
    if (!key) throw new Error('STRIPE_SECRET_KEY が設定されていません');
    _stripe = require('stripe')(key);
  }
  return _stripe;
}

types.setTypeParser(1082, val => val);
types.setTypeParser(1700, val => parseFloat(val));

const app = express();
app.use(cors());

const pool = new Pool(
  process.env.DATABASE_URL
    ? { connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }
    : {
        user: process.env.DB_USER,
        host: process.env.DB_HOST,
        database: process.env.DB_NAME,
        password: process.env.DB_PASSWORD,
        port: process.env.DB_PORT,
      }
);

// DB migration
pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT').catch(() => {});
pool.query('ALTER TABLE fixed_costs ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()').catch(() => {});
pool.query('ALTER TABLE fixed_costs ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL').catch(() => {});

// ===== Stripe Webhook (express.json()より前に置く必要あり) =====
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = getStripe().webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.metadata.userId;
    await pool.query(
      'UPDATE users SET is_premium = true, stripe_customer_id = $2 WHERE id = $1',
      [userId, session.customer]
    );
  } else if (event.type === 'customer.subscription.deleted') {
    const customerId = event.data.object.customer;
    await pool.query(
      'UPDATE users SET is_premium = false WHERE stripe_customer_id = $1',
      [customerId]
    );
  }
  res.json({ received: true });
});

app.use(express.json());

// ===== Stripe Checkout =====
app.post('/api/create-checkout-session', authenticateToken, async (req, res) => {
  try {
    const session = await getStripe().checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      mode: 'subscription',
      success_url: `${process.env.FRONTEND_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/`,
      metadata: { userId: req.user.userId.toString() },
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/verify-payment', authenticateToken, async (req, res) => {
  const { sessionId } = req.body;
  try {
    const session = await getStripe().checkout.sessions.retrieve(sessionId);
    if (session.payment_status === 'paid' && session.metadata.userId === req.user.userId.toString()) {
      await pool.query(
        'UPDATE users SET is_premium = true, stripe_customer_id = $2 WHERE id = $1',
        [req.user.userId, session.customer]
      );
      const newToken = jwt.sign(
        { userId: req.user.userId, isPremium: true },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );
      res.json({ success: true, token: newToken });
    } else {
      res.status(400).json({ error: '支払いが確認できませんでした' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== Stripe カスタマーポータル =====
app.post('/api/create-portal-session', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT stripe_customer_id FROM users WHERE id = $1', [req.user.userId]);
    const customerId = result.rows[0]?.stripe_customer_id;
    if (!customerId) return res.status(400).json({ error: 'サブスク情報が見つかりません' });
    const session = await getStripe().billingPortal.sessions.create({
      customer: customerId,
      return_url: `${process.env.FRONTEND_URL}/settings`,
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== transactions =====
app.get('/api/transactions', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const result = await pool.query('SELECT * FROM transactions WHERE user_id = $1 ORDER BY date DESC', [userId]);
  res.json(result.rows);
});

app.post('/api/transactions', authenticateToken, async (req, res) => {
  const { type, amount, category, date } = req.body;
  const userId = req.user.userId;
  const result = await pool.query(
    'INSERT INTO transactions (type, amount, category, date, user_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
    [type, amount, category, date, userId]
  );
  res.json(result.rows[0]);
});

app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.userId;
  await pool.query('DELETE FROM transactions WHERE id = $1 AND user_id = $2', [id, userId]);
  res.sendStatus(204);
});

app.put('/api/transactions/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { type, amount, category, date } = req.body;
  const userId = req.user.userId;
  const result = await pool.query(
    'UPDATE transactions SET type = $1, amount = $2, category = $3, date = $4 WHERE id = $5 AND user_id = $6 RETURNING *',
    [type, amount, category, date, id, userId]
  );
  res.json(result.rows[0]);
});

// ===== fixed_costs =====
app.get('/api/fixed-costs', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const result = await pool.query(
    'SELECT * FROM fixed_costs WHERE user_id = $1 AND deleted_at IS NULL ORDER BY billing_day ASC',
    [userId]
  );
  res.json(result.rows);
});

app.get('/api/fixed-costs/history', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const result = await pool.query(`
    WITH months AS (
      SELECT generate_series(
        date_trunc('month', COALESCE((SELECT MIN(created_at) FROM fixed_costs WHERE user_id = $1), NOW())),
        date_trunc('month', NOW()),
        interval '1 month'
      ) AS month
    )
    SELECT
      to_char(m.month, 'YYYY-MM') AS month,
      COALESCE(SUM(fc.amount), 0) AS total
    FROM months m
    LEFT JOIN fixed_costs fc ON
      fc.user_id = $1 AND
      date_trunc('month', fc.created_at) <= m.month AND
      (fc.deleted_at IS NULL OR date_trunc('month', fc.deleted_at) > m.month)
    GROUP BY m.month
    ORDER BY m.month
  `, [userId]);
  res.json(result.rows);
});

app.post('/api/fixed-costs', authenticateToken, async (req, res) => {
  const { name, amount, category, billing_day, memo } = req.body;
  const userId = req.user.userId;
  const result = await pool.query(
    'INSERT INTO fixed_costs (name, amount, category, billing_day, memo, user_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
    [name, amount, category, (billing_day !== '' && billing_day != null) ? billing_day : null, memo || null, userId]
  );
  res.json(result.rows[0]);
});

app.delete('/api/fixed-costs/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.userId;
  await pool.query(
    'UPDATE fixed_costs SET deleted_at = NOW() WHERE id = $1 AND user_id = $2',
    [id, userId]
  );
  res.sendStatus(204);
});

app.put('/api/fixed-costs/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, amount, category, billing_day, memo } = req.body;
  const userId = req.user.userId;
  const result = await pool.query(
    'UPDATE fixed_costs SET name = $1, amount = $2, category = $3, billing_day = $4, memo = $5 WHERE id = $6 AND user_id = $7 RETURNING *',
    [name, amount, category, (billing_day !== '' && billing_day != null) ? billing_day : null, memo || null, id, userId]
  );
  res.json(result.rows[0]);
});

// ===== auth =====
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const result = await pool.query(
    'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *',
    [username, hashedPassword]
  );
  res.json(result.rows[0]);
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  const user = result.rows[0];
  if (!user) return res.status(400).json({ message: 'ユーザーが存在しません' });
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return res.status(400).json({ message: 'パスワードが正しくありません' });
  const token = jwt.sign({ userId: user.id, isPremium: user.is_premium }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, isPremium: user.is_premium });
});

app.listen(3001, () => {
  console.log('サーバー起動: http://localhost:3001');
});

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: '認証が必要です' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'tokenが無効です' });
    req.user = user;
    next();
  });
}
