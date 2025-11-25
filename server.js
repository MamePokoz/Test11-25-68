// server.js
require('dotenv').config(); // โหลดค่าจาก .env

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt'); //เพิ่ม bcrypt
const app = express();
const verifyToken = require('./middleware/auth');

app.use(express.json());
const jwt = require("jsonwebtoken");

// ใช้ค่าจาก .env
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

// ----------------------
// Middleware ตรวจสอบ Token
// ----------------------
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.customer = decoded; // เก็บข้อมูล user ไว้ใช้ต่อ
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}


app.get('/ping', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT NOW() AS now');
    res.json({ status: 'ok', time: rows[0].now });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});
// ----------------------
// Register
// ----------------------
app.post("/auth/register", async (req, res) => {
  const { firstname, lastname, username, password, address, phone, email } = req.body;

  const hash = await bcrypt.hash(password, 10);

  await db.query(
    "INSERT INTO tbl_customers (firstname, lastname, username, password, address, phone, email) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [firstname, lastname, username, hash, address, phone, email]
  );

  res.json({ message: "Register success" });
});

// ----------------------
// Login
// ----------------------
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  const [rows] = await db.query(
    "SELECT * FROM tbl_customers WHERE username = ?",
    [username]
  );

  if (rows.length === 0)
    return res.status(400).json({ message: "Username not found" });

  const customer = rows[0];

  const match = await bcrypt.compare(password, customer.password);
  if (!match) return res.status(400).json({ message: "Password incorrect" });

  const token = jwt.sign(
    { id: customer.id, firstname: customer.firstname },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ token });
});

// ----------------------
// GET customers (ต้องใช้ token)
// ----------------------
app.get("/customers", auth, async (req, res) => {
  const [rows] = await db.query(
    "SELECT id, firstname, username ,password FROM tbl_customers"
  );
  res.json(rows);
});

// ----------------------
// GET menus + restaurants (join)
// ----------------------
app.get("/menus", async (req, res) => {
  const [rows] = await db.query(`
    SELECT m.id, m.menu_name, r.restaurants_name, m.price
    FROM tbl_menus m
    JOIN tbl_restaurants r ON m.restaurant_id = r.id
  `);

  res.json(rows);
});

// ----------------------
// POST orders (ต้องใช้ token)
// ----------------------
app.post("/orders", auth, async (req, res) => {
  const { restaurant_id, menu_id, quantity } = req.body;

  // ดึงราคาเมนู
  const [menuData] = await db.query(
    "SELECT price FROM tbl_menus WHERE id = ?",
    [menu_id]
  );

  const price = menuData[0].price;
  const total_price = price * quantity;

  // บันทึกคำสั่งซื้อ พร้อมใส่ status = 'in progress'
  await db.query(
    "INSERT INTO tbl_orders (customer_id, restaurant_id, menu_id, quantity, total_price, status) VALUES (?, ?, ?, ?, ?, ?)",
    [req.customer.id, restaurant_id, menu_id, quantity, total_price, "in progress"]
  );

  res.json({ message: "Order success", total_price });
});

// ----------------------
// GET orders summary (ต้องใช้ token)
// ----------------------
app.get("/orders/summary", auth, async (req, res) => {
  const customerId = req.customer.id;

  const [[result]] = await db.query(`
    SELECT c.firstname AS customer_name, SUM(o.total_price) AS total_amount
    FROM tbl_orders o
    JOIN tbl_customers c ON o.customer_id = c.id
    WHERE o.customer_id = ?
  `, [customerId]);

  res.json(result);
});

// ----------------------
app.listen(3000, () => console.log("Server running on port 3000"));
