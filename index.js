require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const { types } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
types.setTypeParser(1082, val => val); // DATE型を文字列のまま返す

const app = express();
app.use(express.json());
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
  const result = await pool.query('SELECT * FROM fixed_costs WHERE user_id = $1 ORDER BY billing_day ASC', [userId]);
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
  await pool.query('DELETE FROM fixed_costs WHERE id = $1 AND user_id = $2', [id, userId]);
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
  if (!user) {
    return res.status(400).json({ message: 'ユーザーが存在しません' });
  }
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ message: 'パスワードが正しくありません' });
  }
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
    next(); // 問題なければ次の処理へ
  });
}