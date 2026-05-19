const featureB = require("./feature-b.js");

function users() {
  return featureB.names().map((name) => ({ name }));
}

module.exports = { users };
