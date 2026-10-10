// Tiny Express app used only as a ThreatSketch test fixture. Not for production.
const express = require("express");
const jwt = require("jsonwebtoken");
const users = require("./routes/users");

const app = express();
app.use(express.json());

app.post("/api/login", (req, res) => {
  const token = jwt.sign({ user: req.body.username }, process.env.JWT_SECRET);
  res.json({ token });
});

app.use("/api/users", users);

app.get("/health", (req, res) => res.json({ ok: true }));

app.listen(process.env.PORT || 3000);
