const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SECRET_KEY = "supersecretkey"; // change in production

// In-memory storage (use a DB in real app)
let users = [
  { username: "admin", password: bcrypt.hashSync("admin123", 8), role: "admin" }
];
let resources = [];

// Middleware: verify token
function verifyToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(403).json({ message: "No token provided." });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Unauthorized." });
    req.user = decoded;
    next();
  });
}

// Middleware: check admin
function verifyAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required." });
  }
  next();
}

/* =====================
   ADMIN ROUTES
===================== */

// Admin login
app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.role === "admin");
  if (!user) return res.status(404).json({ message: "Admin not found" });

  const passwordIsValid = bcrypt.compareSync(password, user.password);
  if (!passwordIsValid) return res.status(401).json({ message: "Invalid password" });

  const token = jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: "2h" });
  res.json({ token, message: "Admin login successful" });
});

// Create user (admin only)
app.post("/api/admin/users/create", verifyToken, verifyAdmin, (req, res) => {
  const { username, password } = req.body;
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ message: "User already exists" });
  }
  const hashed = bcrypt.hashSync(password, 8);
  users.push({ username, password: hashed, role: "user" });
  res.json({ message: "User created successfully" });
});

// Add resource (admin only)
app.post("/api/admin/resources/create", verifyToken, verifyAdmin, (req, res) => {
  const { title, link } = req.body;
  resources.push({ id: resources.length + 1, title, link });
  res.json({ message: "Resource added successfully" });
});

/* =====================
   USER ROUTES
===================== */

// User login
app.post("/api/users/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.role === "user");
  if (!user) return res.status(404).json({ message: "User not found" });

  const passwordIsValid = bcrypt.compareSync(password, user.password);
  if (!passwordIsValid) return res.status(401).json({ message: "Invalid password" });

  const token = jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: "2h" });
  res.json({ token, message: "Login successful" });
});

// Get resources (public list)
app.get("/api/resources", (req, res) => {
  res.json(resources);
});

app.listen(3000, () => console.log("🚀 Server running at http://localhost:3000"));