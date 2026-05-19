"use strict";

const { spawn, spawnSync } = require("child_process");
const path = require("path");

const root = path.resolve(__dirname, "..");

function findPython() {
  for (const candidate of ["python3", "python"]) {
    const probe = spawnSync(candidate, ["-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"], {
      stdio: "ignore"
    });
    if (!probe.error && probe.status === 0) {
      return candidate;
    }
  }
  throw new Error("Python 3.11 or newer is required for tests.");
}

const commands = [
  [process.execPath, ["tests/test_install.js"]],
  [findPython(), ["-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"]]
];

let remaining = commands.length;
let exitCode = 0;

for (const [command, args] of commands) {
  const child = spawn(command, args, { cwd: root, stdio: "inherit" });
  child.on("exit", (code) => {
    if (code !== 0) {
      exitCode = code || 1;
    }
    remaining -= 1;
    if (remaining === 0) {
      process.exitCode = exitCode;
    }
  });
  child.on("error", (error) => {
    console.error(error.message);
    exitCode = 1;
    remaining -= 1;
    if (remaining === 0) {
      process.exitCode = exitCode;
    }
  });
}
