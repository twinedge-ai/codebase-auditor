const express = require("express");
const featureA = require("./feature-a.js");

const app = express();

app.get("/users", (_req, res) => {
  res.json(featureA.users());
});

module.exports = app;
