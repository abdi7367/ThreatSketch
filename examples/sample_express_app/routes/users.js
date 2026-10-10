const express = require("express");
const router = express.Router();

const users = [];

router.get("/", (req, res) => res.json(users));

router.post("/", (req, res) => {
  users.push(req.body);
  res.status(201).json(req.body);
});

router.delete("/:id", (req, res) => {
  users.splice(Number(req.params.id), 1);
  res.status(204).end();
});

module.exports = router;
