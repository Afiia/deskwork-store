const path = require('path');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const db = new Database(path.join(__dirname, 'shop.db'));   // created automatically
db.pragma('foreign_keys = ON');
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
if (!process.env.JWT_SECRET) console.warn('Warning: set JWT_SECRET before deploying.');
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const now = `strftime('%Y-%m-%dT%H:%M:%SZ','now')`;
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
  created_at TEXT DEFAULT (${now})
);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  price REAL NOT NULL CHECK (price >= 0),
  stock INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
  image_url TEXT DEFAULT '',
  created_at TEXT DEFAULT (${now})
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  total REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','paid','shipped','delivered','cancelled')),
  shipping_address TEXT NOT NULL,
  created_at TEXT DEFAULT (${now})
);
CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id INTEGER NOT NULL REFERENCES products(id),
  quantity INTEGER NOT NULL CHECK (quantity > 0),
  unit_price REAL NOT NULL
);`);

// seed admin + sample products on first run
if (!db.prepare(`SELECT 1 FROM users WHERE role='admin'`).get()) {
  db.prepare(`INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,'admin')`)
    .run('Admin', 'admin@shop.test', bcrypt.hashSync('admin123', 10));
  console.log('Seeded admin: admin@shop.test / admin123  (change this!)');
}
if (!db.prepare("SELECT 1 FROM pragma_table_info('products') WHERE name='category'").get())
  db.exec("ALTER TABLE products ADD COLUMN category TEXT DEFAULT ''");

db.exec(`
CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id),
  rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
  comment TEXT DEFAULT '',
  created_at TEXT DEFAULT (${now}),
  UNIQUE (product_id, user_id)
);
CREATE TABLE IF NOT EXISTS coupons (
  code TEXT PRIMARY KEY,
  percent INTEGER NOT NULL CHECK (percent BETWEEN 1 AND 90),
  active INTEGER NOT NULL DEFAULT 1
);`);
if (!db.prepare("SELECT 1 FROM pragma_table_info('orders') WHERE name='coupon'").get())
  db.exec("ALTER TABLE orders ADD COLUMN coupon TEXT; ALTER TABLE orders ADD COLUMN discount REAL NOT NULL DEFAULT 0");
db.exec("INSERT OR IGNORE INTO coupons (code,percent) VALUES ('WELCOME10',10),('DESK20',20)");

// Seed products (added by name if missing; fills in images for products that have none)
const SEED = [
  ['Linen notebook', 'A5, 192 dotted pages, lies flat.', 14.5, 40, '/images/notebook.svg'],
  ['Brass pen', 'Refillable, weighted barrel.', 32, 15, '/images/pen.svg'],
  ['Graphite set', 'Six grades, tin case.', 9.9, 60, '/images/graphite.svg'],
  ['Desk mat', 'Wool felt, 80 x 40 cm.', 44, 8, '/images/deskmat.svg'],
  ['Ceramic mug', 'Hand-glazed, holds 350 ml.', 18, 30, '/images/mug.svg'],
  ['Desk lamp', 'Adjustable arm, warm LED.', 56, 12, '/images/lamp.svg'],
  ['Canvas tote', 'Heavy cotton, fits a laptop.', 22, 25, '/images/tote.svg'],
  ['Sticky notes', 'Three colours, 300 sheets.', 6.5, 100, '/images/stickynotes.svg']
];
const findP = db.prepare('SELECT id,image_url,category FROM products WHERE name=?');
const addP = db.prepare('INSERT INTO products (name,description,price,stock,image_url,category) VALUES (?,?,?,?,?,?)');
const setImg = db.prepare('UPDATE products SET image_url=? WHERE id=?');
const CATS = { 'Linen notebook': 'Paper', 'Sticky notes': 'Paper', 'Brass pen': 'Writing', 'Graphite set': 'Writing',
  'Desk mat': 'Desk gear', 'Desk lamp': 'Desk gear', 'Ceramic mug': 'Lifestyle', 'Canvas tote': 'Lifestyle' };
const setCat = db.prepare('UPDATE products SET category=? WHERE id=?');
for (const [n, d, p, s, img] of SEED) {
  const r = findP.get(n);
  if (!r) addP.run(n, d, p, s, img, CATS[n]);
  else {
    if (!r.image_url) setImg.run(img, r.id);
    if (!r.category) setCat.run(CATS[n], r.id);
  }
}

// ---------- helpers ----------
const wrap = fn => (req, res) => {
  try { fn(req, res); }
  catch (e) {
    if (e.status) return res.status(e.status).json({ error: e.msg });
    console.error(e); res.status(500).json({ error: 'Server error' });
  }
};
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: 'Login required' }); }
}
const admin = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only' });
const sign = u => jwt.sign({ id: u.id, role: u.role, name: u.name }, SECRET, { expiresIn: '7d' });

// ---------- auth ----------
const fails = new Map();
app.post('/api/auth/register', wrap((req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 6)
    return res.status(400).json({ error: 'Name, email and a password of 6+ characters are required' });
  try {
    const r = db.prepare('INSERT INTO users (name,email,password_hash) VALUES (?,?,?)')
      .run(name, email.toLowerCase(), bcrypt.hashSync(password, 10));
    const user = { id: r.lastInsertRowid, name, role: 'user' };
    res.status(201).json({ token: sign(user), user });
  } catch (e) {
    if (String(e.code).startsWith('SQLITE_CONSTRAINT'))
      return res.status(409).json({ error: 'Email already registered' });
    throw e;
  }
}));

app.post('/api/auth/login', wrap((req, res) => {
  const { email, password } = req.body;
  // basic brute-force protection: 5 failed attempts per email+IP per 15 minutes
  const key = req.ip + '|' + (email || '').toLowerCase(), f = fails.get(key);
  if (f && f.n >= 5 && Date.now() - f.t < 15 * 60 * 1000)
    return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
  const u = db.prepare('SELECT * FROM users WHERE email=?').get((email || '').toLowerCase());
  if (!u || !bcrypt.compareSync(password || '', u.password_hash)) {
    fails.set(key, { n: (f && Date.now() - f.t < 15 * 60 * 1000 ? f.n : 0) + 1, t: Date.now() });
    return res.status(401).json({ error: 'Wrong email or password' });
  }
  fails.delete(key);
  res.json({ token: sign(u), user: { id: u.id, name: u.name, role: u.role } });
}));

// ---------- products ----------
app.get('/api/products', wrap((req, res) => {
  res.json(db.prepare('SELECT p.*, (SELECT ROUND(AVG(rating),1) FROM reviews r WHERE r.product_id=p.id) AS rating, (SELECT COUNT(*) FROM reviews r WHERE r.product_id=p.id) AS reviews FROM products p WHERE p.name LIKE ? ORDER BY p.id DESC')
    .all(`%${req.query.q || ''}%`));
}));

const validProduct = b =>
  b.name && Number(b.price) >= 0 && Number.isInteger(Number(b.stock)) && Number(b.stock) >= 0;

app.post('/api/products', auth, admin, wrap((req, res) => {
  const b = req.body;
  if (!validProduct(b)) return res.status(400).json({ error: 'Name, price and stock are required' });
  const r = db.prepare('INSERT INTO products (name,description,price,stock,image_url,category) VALUES (?,?,?,?,?,?)')
    .run(b.name, b.description || '', Number(b.price), Number(b.stock), b.image_url || '', b.category || '');
  res.status(201).json(db.prepare('SELECT * FROM products WHERE id=?').get(r.lastInsertRowid));
}));

app.put('/api/products/:id', auth, admin, wrap((req, res) => {
  const b = req.body;
  if (!validProduct(b)) return res.status(400).json({ error: 'Name, price and stock are required' });
  const r = db.prepare('UPDATE products SET name=?,description=?,price=?,stock=?,image_url=?,category=? WHERE id=?')
    .run(b.name, b.description || '', Number(b.price), Number(b.stock), b.image_url || '', b.category || '', req.params.id);
  r.changes ? res.json(db.prepare('SELECT * FROM products WHERE id=?').get(req.params.id))
            : res.status(404).json({ error: 'Product not found' });
}));

app.delete('/api/products/:id', auth, admin, wrap((req, res) => {
  try {
    const r = db.prepare('DELETE FROM products WHERE id=?').run(req.params.id);
    r.changes ? res.json({ ok: true }) : res.status(404).json({ error: 'Product not found' });
  } catch (e) {
    if (String(e.code).startsWith('SQLITE_CONSTRAINT'))
      return res.status(409).json({ error: 'Product appears in orders. Set its stock to 0 instead.' });
    throw e;
  }
}));

// ---------- reviews, coupons, stats ----------
app.get('/api/products/:id/reviews', wrap((req, res) => {
  res.json(db.prepare(`SELECT r.rating, r.comment, r.created_at, u.name FROM reviews r
    JOIN users u ON u.id=r.user_id WHERE r.product_id=? ORDER BY r.id DESC`).all(req.params.id));
}));

app.post('/api/products/:id/reviews', auth, wrap((req, res) => {
  const rating = Number(req.body.rating), comment = String(req.body.comment || '').slice(0, 500);
  if (!Number.isInteger(rating) || rating < 1 || rating > 5)
    return res.status(400).json({ error: 'Choose a rating from 1 to 5' });
  const bought = db.prepare(`SELECT 1 FROM order_items i JOIN orders o ON o.id=i.order_id
    WHERE i.product_id=? AND o.user_id=? AND o.status!='cancelled'`).get(req.params.id, req.user.id);
  if (!bought) return res.status(403).json({ error: 'Only customers who bought this product can review it' });
  db.prepare(`INSERT INTO reviews (product_id,user_id,rating,comment) VALUES (?,?,?,?)
    ON CONFLICT(product_id,user_id) DO UPDATE SET rating=excluded.rating, comment=excluded.comment`)
    .run(req.params.id, req.user.id, rating, comment);
  res.status(201).json({ ok: true });
}));

const getCoupon = code =>
  db.prepare('SELECT code,percent FROM coupons WHERE code=? AND active=1').get(String(code || '').trim().toUpperCase());
app.post('/api/coupons/validate', wrap((req, res) => {
  const c = getCoupon(req.body.code);
  c ? res.json(c) : res.status(404).json({ error: 'That code is not valid' });
}));

app.get('/api/admin/stats', auth, admin, wrap((req, res) => {
  const days = db.prepare(`SELECT substr(created_at,1,10) AS day, ROUND(SUM(total),2) AS revenue FROM orders
    WHERE status!='cancelled' GROUP BY day ORDER BY day DESC LIMIT 7`).all().reverse();
  const top = db.prepare(`SELECT p.name, SUM(i.quantity) AS sold FROM order_items i
    JOIN orders o ON o.id=i.order_id JOIN products p ON p.id=i.product_id
    WHERE o.status!='cancelled' GROUP BY p.id ORDER BY sold DESC LIMIT 5`).all();
  res.json({ days, top });
}));

// ---------- orders ----------
// better-sqlite3 transactions are synchronous, so stock checks can't race.
const placeOrder = db.transaction((userId, items, address, coupon) => {
  let total = 0;
  const lines = [];
  for (const it of items) {
    const qty = Number(it.quantity);
    if (!Number.isInteger(qty) || qty < 1) throw { status: 400, msg: 'Invalid quantity' };
    const p = db.prepare('SELECT * FROM products WHERE id=?').get(it.product_id);
    if (!p) throw { status: 400, msg: 'A product in your cart no longer exists' };
    if (p.stock < qty) throw { status: 409, msg: `Only ${p.stock} of "${p.name}" left` };
    db.prepare('UPDATE products SET stock = stock - ? WHERE id=?').run(qty, p.id);
    total += p.price * qty;
    lines.push([p.id, qty, p.price]);
  }
  let discount = 0, code = null;
  if (coupon) {
    const c = getCoupon(coupon);
    if (!c) throw { status: 400, msg: 'That coupon code is not valid' };
    discount = Math.round(total * c.percent) / 100; code = c.code;
  }
  const o = db.prepare('INSERT INTO orders (user_id,total,shipping_address,coupon,discount) VALUES (?,?,?,?,?)')
    .run(userId, Math.round((total - discount) * 100) / 100, address, code, discount);
  const ins = db.prepare('INSERT INTO order_items (order_id,product_id,quantity,unit_price) VALUES (?,?,?,?)');
  lines.forEach(l => ins.run(o.lastInsertRowid, ...l));
  return db.prepare('SELECT * FROM orders WHERE id=?').get(o.lastInsertRowid);
});

app.post('/api/orders', auth, wrap((req, res) => {
  const { items, shipping_address, coupon } = req.body;
  if (!Array.isArray(items) || !items.length || !shipping_address)
    return res.status(400).json({ error: 'Cart and shipping address are required' });
  res.status(201).json(placeOrder(req.user.id, items, shipping_address, coupon));
}));

// Users see their own orders; admins see everyone's.
app.get('/api/orders', auth, wrap((req, res) => {
  const isAdmin = req.user.role === 'admin';
  const orders = db.prepare(
    `SELECT o.*, u.name AS customer FROM orders o JOIN users u ON u.id=o.user_id
     ${isAdmin ? '' : 'WHERE o.user_id=?'} ORDER BY o.id DESC`).all(...(isAdmin ? [] : [req.user.id]));
  const itemsStmt = db.prepare(
    `SELECT p.name, i.quantity, i.unit_price FROM order_items i
     JOIN products p ON p.id=i.product_id WHERE i.order_id=?`);
  orders.forEach(o => { o.items = itemsStmt.all(o.id); });
  res.json(orders);
}));

// Cancelling puts the items back in stock (only before shipping).
const cancelOrder = db.transaction(id => {
  const o = db.prepare('SELECT * FROM orders WHERE id=?').get(id);
  if (!o) throw { status: 404, msg: 'Order not found' };
  if (o.status === 'cancelled') throw { status: 409, msg: 'Order is already cancelled' };
  if (['shipped', 'delivered'].includes(o.status)) throw { status: 409, msg: 'Shipped orders can no longer be cancelled' };
  db.prepare('SELECT product_id,quantity FROM order_items WHERE order_id=?').all(id)
    .forEach(i => db.prepare('UPDATE products SET stock=stock+? WHERE id=?').run(i.quantity, i.product_id));
  db.prepare("UPDATE orders SET status='cancelled' WHERE id=?").run(id);
});

app.post('/api/orders/:id/cancel', auth, wrap((req, res) => {
  const o = db.prepare('SELECT user_id FROM orders WHERE id=?').get(req.params.id);
  if (!o || (o.user_id !== req.user.id && req.user.role !== 'admin'))
    return res.status(404).json({ error: 'Order not found' });
  cancelOrder(req.params.id);
  res.json({ ok: true });
}));

app.patch('/api/orders/:id/status', auth, admin, wrap((req, res) => {
  const ok = ['pending', 'paid', 'shipped', 'delivered', 'cancelled'];
  if (!ok.includes(req.body.status)) return res.status(400).json({ error: 'Invalid status' });
  if (req.body.status === 'cancelled') { cancelOrder(req.params.id); return res.json({ ok: true }); }
  const cur = db.prepare('SELECT status FROM orders WHERE id=?').get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'Order not found' });
  if (cur.status === 'cancelled') return res.status(409).json({ error: 'Cancelled orders cannot be changed' });
  db.prepare('UPDATE orders SET status=? WHERE id=?').run(req.body.status, req.params.id);
  res.json({ ok: true });
}));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`http://localhost:${port}`));
