const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");

const app = express();

app.use(express.json());
app.use(cors());

const SECRET_KEY = "mysecretkey";

// Fake DB
const users = [];

// Register
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Missing fields" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });

  res.json({ message: "User registered successfully" });
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ message: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });

  res.json({ token });
});

// Middleware
function verifyToken(req, res, next) {
  const header = req.headers["authorization"];

  if (!header) return res.sendStatus(403);

  const token = header.split(" ")[1];

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.sendStatus(403);

    req.user = decoded;
    next();
  });
}

// Protected route
app.get("/protected", verifyToken, (req, res) => {
  res.json({
    message: "Protected data accessed",
    user: req.user
  });
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});