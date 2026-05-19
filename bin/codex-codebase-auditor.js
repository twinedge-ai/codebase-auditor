#!/usr/bin/env node
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const SKILL_SRC = path.join(ROOT, "skill", "codebase-auditor");
const PY_CLI = path.join(SKILL_SRC, "scripts", "auditor", "cli.py");
const BOOLEAN_FLAGS = new Set([
  "dry-run",
  "silent",
  "force",
  "allow-network",
  "offline",
  "include-diagrams",
  "no-diagrams",
  "allow-perf",
  "allow-mocks",
  "allow-private-network",
  "run-lighthouse",
  "run-load-test",
  "run-benchmarks",
  "confirm-benchmarks",
  "lighthouse-no-sandbox",
  "json"
]);
const REPEATABLE_FLAGS = new Set(["load-url", "test-command"]);
const REPO_CONFIG_TEMPLATE = {
  report: {
    includeMermaidDiagrams: false,
    includeRemediationPlan: true
  }
};

function usage() {
  console.log(`codex-codebase-auditor

Usage:
  codex-codebase-auditor install [--path <skills-dir>] [--dry-run] [--silent]
  codex-codebase-auditor init [repo] [--force]
  codex-codebase-auditor scan [repo] [--profile quick-static|complexity|security|architecture|performance|full] [--format markdown,json,html] [--out report.md|report.html] [--json-out report.json] [--allow-network|--offline] [--include-diagrams] [--allow-perf] [--lighthouse-no-sandbox]
  codex-codebase-auditor fix [repo] --finding <finding-id> [--dry-run] [--json] [--test-command <cmd>]

Examples:
  codex-codebase-auditor install
  codex-codebase-auditor init .
  codex-codebase-auditor scan . --out codebase-audit-report.md
  codex-codebase-auditor fix . --finding complexity-py-membership-literal-abc12345
`);
}

function parseArgs(argv) {
  const flags = {};
  const positional = [];

  function setFlag(key, value) {
    if (!REPEATABLE_FLAGS.has(key)) {
      if (Object.prototype.hasOwnProperty.call(flags, key)) {
        throw new Error(`Duplicate flag is not allowed: --${key}`);
      }
      flags[key] = value;
      return;
    }
    if (flags[key] === undefined) {
      flags[key] = [value];
    } else {
      flags[key].push(value);
    }
  }

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }

    const eq = arg.indexOf("=");
    if (eq !== -1) {
      const key = arg.slice(2, eq);
      if (BOOLEAN_FLAGS.has(key)) {
        throw new Error(`Flag does not take a value: --${key}`);
      }
      setFlag(key, arg.slice(eq + 1));
      continue;
    }

    const key = arg.slice(2);
    if (BOOLEAN_FLAGS.has(key)) {
      setFlag(key, true);
      continue;
    }
    const next = argv[i + 1];
    if (next && !next.startsWith("--")) {
      setFlag(key, next);
      i += 1;
    } else {
      setFlag(key, true);
    }
  }

  return { flags, positional };
}

function ensureSourceSkill() {
  const skillMd = path.join(SKILL_SRC, "SKILL.md");
  if (!fs.existsSync(skillMd)) {
    throw new Error(`Missing skill source at ${skillMd}`);
  }
}

function isAuditorSkillDir(dir) {
  const skillMd = path.join(dir, "SKILL.md");
  if (!fs.existsSync(skillMd)) {
    return false;
  }
  const content = fs.readFileSync(skillMd, "utf8");
  return /^name:\s*codebase-auditor\s*$/m.test(content);
}

function assertSafeInstallTarget(dest) {
  if (!fs.existsSync(dest)) {
    return;
  }
  const metadata = fs.lstatSync(dest);
  if (!metadata.isDirectory() || !isAuditorSkillDir(dest)) {
    throw new Error(`Refusing to overwrite non-codebase-auditor install target: ${dest}`);
  }
}

function copyDir(src, dest) {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  assertSafeInstallTarget(dest);
  fs.rmSync(dest, { recursive: true, force: true });
  fs.cpSync(src, dest, {
    recursive: true,
    filter: (source) => {
      const base = path.basename(source);
      return base !== "__pycache__" && !base.endsWith(".pyc") && !base.endsWith(".pyo");
    }
  });
}

function defaultSkillsDir() {
  const codexHome = process.env.CODEX_HOME || path.join(os.homedir(), ".codex");
  return path.join(codexHome, "skills");
}

function installCommand(argv) {
  const { flags } = parseArgs(argv);
  ensureSourceSkill();

  const skillsDir = path.resolve(flags.path || defaultSkillsDir());
  const dest = path.join(skillsDir, "codebase-auditor");

  if (flags["dry-run"]) {
    if (!flags.silent) {
      console.log(`Would install ${SKILL_SRC} -> ${dest}`);
    }
    return 0;
  }

  copyDir(SKILL_SRC, dest);
  if (!flags.silent) {
    console.log(`Installed codebase-auditor skill to ${dest}`);
    console.log("Try: Use $codebase-auditor to audit this repository and generate a full engineering report.");
  }
  return 0;
}

function initCommand(argv) {
  const { flags, positional } = parseArgs(argv);
  const repo = path.resolve(positional[0] || process.cwd());
  const dest = path.join(repo, ".codebase-auditor.json");

  if (!fs.existsSync(repo) || !fs.statSync(repo).isDirectory()) {
    throw new Error(`Repository path does not exist or is not a directory: ${repo}`);
  }
  if (fs.existsSync(dest)) {
    const existing = fs.lstatSync(dest);
    if (existing.isSymbolicLink() || !existing.isFile()) {
      throw new Error(`Refusing to overwrite unsafe config path: ${dest}`);
    }
    if (!flags.force) {
      console.log(`Config already exists: ${dest}`);
      console.log("Use --force to overwrite it.");
      return 0;
    }
  }

  writeFileSafely(dest, `${JSON.stringify(REPO_CONFIG_TEMPLATE, null, 2)}\n`);
  console.log(`Created ${dest}`);
  return 0;
}

function writeFileSafely(dest, content) {
  const dir = path.dirname(dest);
  const base = path.basename(dest);
  let fd = null;
  let temp = null;
  try {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      temp = path.join(dir, `.${base}.${process.pid}.${crypto.randomBytes(8).toString("hex")}`);
      try {
        fd = fs.openSync(temp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o666);
        break;
      } catch (error) {
        if (error.code !== "EEXIST") {
          throw error;
        }
      }
    }
    if (fd === null || temp === null) {
      throw new Error(`Could not allocate a temporary config file in ${dir}`);
    }
    fs.writeFileSync(fd, content, "utf8");
    fs.closeSync(fd);
    fd = null;
    fs.renameSync(temp, dest);
    temp = null;
  } finally {
    if (fd !== null) {
      fs.closeSync(fd);
    }
    if (temp !== null && fs.existsSync(temp)) {
      fs.rmSync(temp, { force: true });
    }
  }
}

function executableNames(candidate) {
  if (process.platform !== "win32" || path.extname(candidate)) {
    return [candidate];
  }
  const pathExt = process.env.PATHEXT || ".EXE;.CMD;.BAT;.COM";
  return pathExt.split(";").filter(Boolean).map((ext) => `${candidate}${ext.toLowerCase()}`);
}

function isExecutableFile(file) {
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile()) {
      return false;
    }
    return process.platform === "win32" || (stat.mode & 0o111) !== 0;
  } catch (_error) {
    return false;
  }
}

function resolveFromAbsolutePath(candidate) {
  const pathValue = process.env.PATH || "";
  const names = executableNames(candidate);
  for (const entry of pathValue.split(path.delimiter)) {
    if (!entry || !path.isAbsolute(entry)) {
      continue;
    }
    const resolved = resolveExecutableInPathEntry(entry, names);
    if (resolved) {
      return resolved;
    }
  }
  return null;
}

function resolveExecutableInPathEntry(entry, names) {
  for (const name of names) {
    const file = path.join(entry, name);
    if (isExecutableFile(file)) {
      return file;
    }
  }
  return null;
}

function findPython() {
  for (const candidate of ["python3", "python"]) {
    const executable = resolveFromAbsolutePath(candidate);
    if (!executable) {
      continue;
    }
    const probe = spawnSync(executable, ["-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"], { encoding: "utf8" });
    if (!probe.error && probe.status === 0) {
      return executable;
    }
  }
  throw new Error("Python 3.11 or newer is required for scanning.");
}

function scanCommand(argv) {
  const pyArgs = [PY_CLI, "scan", ...argv];

  const result = spawnSync(findPython(), pyArgs, {
    stdio: "inherit",
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" }
  });
  if (result.error) {
    throw result.error;
  }
  return result.status ?? 1;
}

function fixCommand(argv) {
  const pyArgs = [PY_CLI, "fix", ...argv];

  const result = spawnSync(findPython(), pyArgs, {
    stdio: "inherit",
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" }
  });
  if (result.error) {
    throw result.error;
  }
  return result.status ?? 1;
}

function main() {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === "--help" || command === "-h") {
    usage();
    return 0;
  }

  if (command === "install") {
    return installCommand(rest);
  }
  if (command === "init") {
    return initCommand(rest);
  }
  if (command === "scan") {
    return scanCommand(rest);
  }
  if (command === "fix") {
    return fixCommand(rest);
  }

  usage();
  throw new Error(`Unknown command: ${command}`);
}

try {
  process.exitCode = main();
} catch (error) {
  console.error(`Error: ${error.message}`);
  process.exitCode = 1;
}
