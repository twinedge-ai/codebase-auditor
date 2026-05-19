const featureA = require("./feature-a.js");

function names() {
  return featureA ? ["ada"] : [];
}

module.exports = { names };
