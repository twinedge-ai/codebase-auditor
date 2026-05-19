const express = require("express");
const logger = require("../../../shared/logger.js");

const app = express();

app.get("/", (_req, res) => {
  logger.info("home");
  res.send("ok");
});

module.exports = app;
