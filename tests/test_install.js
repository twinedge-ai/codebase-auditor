"use strict";

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const root = path.resolve(__dirname, "..");
const bin = path.join(root, "bin", "codex-codebase-auditor.js");

function run(args, options = {}) {
  return spawnSync(process.execPath, [bin, ...args], {
    cwd: options.cwd || root,
    encoding: "utf8",
    env: { ...process.env, ...(options.env || {}) }
  });
}

const temp = fs.mkdtempSync(path.join(os.tmpdir(), "auditor-install-"));
try {
  const dryRun = run(["install", "--path", path.join(temp, "skills"), "--dry-run"]);
  assert.strictEqual(dryRun.status, 0, dryRun.stderr);
  assert.match(dryRun.stdout, /Would install/);

  const install = run(["install", "--silent"], { env: { CODEX_HOME: temp } });
  assert.strictEqual(install.status, 0, install.stderr);
  assert.ok(fs.existsSync(path.join(temp, "skills", "codebase-auditor", "SKILL.md")));

  const badHome = path.join(temp, "bad-home");
  const badTarget = path.join(badHome, "skills", "codebase-auditor");
  fs.mkdirSync(badTarget, { recursive: true });
  fs.writeFileSync(path.join(badTarget, "README.md"), "do not delete\n", "utf8");
  const refusedInstall = run(["install", "--silent"], { env: { CODEX_HOME: badHome } });
  assert.notStrictEqual(refusedInstall.status, 0);
  assert.ok(fs.existsSync(path.join(badTarget, "README.md")));

  const repo = path.join(temp, "repo");
  fs.mkdirSync(repo);
  const duplicateFlag = run(["init", repo, "--force", "--force"]);
  assert.notStrictEqual(duplicateFlag.status, 0);

  const init = run(["init", repo]);
  assert.strictEqual(init.status, 0, init.stderr);
  const repoConfig = path.join(repo, ".codebase-auditor.json");
  assert.ok(fs.existsSync(repoConfig));
  const payload = JSON.parse(fs.readFileSync(repoConfig, "utf8"));
  assert.deepStrictEqual(Object.keys(payload).sort(), ["report"]);
  assert.ok(!Object.prototype.hasOwnProperty.call(payload, "allowNetwork"));
  assert.ok(!Object.prototype.hasOwnProperty.call(payload, "externalTools"));

  const forcedRepo = path.join(temp, "forced-repo");
  fs.mkdirSync(forcedRepo);
  const forcedInit = run(["init", "--force", forcedRepo], { cwd: temp });
  assert.strictEqual(forcedInit.status, 0, forcedInit.stderr);
  assert.ok(fs.existsSync(path.join(forcedRepo, ".codebase-auditor.json")));
  assert.ok(!fs.existsSync(path.join(temp, ".codebase-auditor.json")));

  const symlinkRepo = path.join(temp, "symlink-repo");
  fs.mkdirSync(symlinkRepo);
  const outsideConfig = path.join(temp, "outside-config.json");
  fs.writeFileSync(outsideConfig, "do not overwrite\n", "utf8");
  fs.symlinkSync(outsideConfig, path.join(symlinkRepo, ".codebase-auditor.json"));
  const refusedSymlinkInit = run(["init", "--force", symlinkRepo]);
  assert.notStrictEqual(refusedSymlinkInit.status, 0);
  assert.match(refusedSymlinkInit.stderr, /Refusing to overwrite unsafe config path/);
  assert.strictEqual(fs.readFileSync(outsideConfig, "utf8"), "do not overwrite\n");

  const hardlinkRepo = path.join(temp, "hardlink-repo");
  fs.mkdirSync(hardlinkRepo);
  const hardlinkOutsideConfig = path.join(temp, "outside-hardlink-config.json");
  fs.writeFileSync(hardlinkOutsideConfig, "do not overwrite hardlink\n", "utf8");
  try {
    fs.linkSync(hardlinkOutsideConfig, path.join(hardlinkRepo, ".codebase-auditor.json"));
    const hardlinkInit = run(["init", "--force", hardlinkRepo]);
    assert.strictEqual(hardlinkInit.status, 0, hardlinkInit.stderr);
    assert.strictEqual(fs.readFileSync(hardlinkOutsideConfig, "utf8"), "do not overwrite hardlink\n");
    assert.deepStrictEqual(Object.keys(JSON.parse(fs.readFileSync(path.join(hardlinkRepo, ".codebase-auditor.json"), "utf8"))).sort(), ["report"]);
  } catch (error) {
    if (error.code !== "EPERM" && error.code !== "EOPNOTSUPP" && error.code !== "EXDEV") {
      throw error;
    }
  }

  const pathRepo = path.join(temp, "path-repo");
  fs.mkdirSync(pathRepo);
  fs.writeFileSync(path.join(pathRepo, "app.js"), "const ok = 1;\n", "utf8");
  const marker = path.join(temp, "relative-path-python-ran");
  const fakePython = path.join(pathRepo, "python3");
  fs.writeFileSync(fakePython, `#!/bin/sh\ntouch ${JSON.stringify(marker)}\nexit 0\n`, "utf8");
  fs.chmodSync(fakePython, 0o755);
  const scanOut = path.join(temp, "scan.json");
  const pathScan = run(["scan", pathRepo, "--profile", "security", "--offline", "--format", "json", "--json-out", scanOut], {
    cwd: pathRepo,
    env: { PATH: `.${path.delimiter}${process.env.PATH || ""}` }
  });
  assert.strictEqual(pathScan.status, 0, pathScan.stderr);
  assert.ok(fs.existsSync(scanOut));
  assert.ok(!fs.existsSync(marker));
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
