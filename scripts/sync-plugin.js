#!/usr/bin/env node
'use strict';
// AgathOS - makes the copies of core/ files that the plugin carries (plugins/agathos/lib/) and puts the version of the program in the
// manifest of the plugin. A plugin is installed on its own, without the rest of this repository, so it needs its own copies.
//   node scripts/sync-plugin.js            make the copies
//   node scripts/sync-plugin.js --check    only say whether they are identical (exit 1 if not)
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const LIB = ['catalog', 'classify', 'textscan', 'untrusted', 'ask', 'util', 'links', 'copies', 'boards', 'supply', 'client', 'mcp'];
const TO = path.join(ROOT, 'plugins', 'agathos', 'lib');
const MANIFEST = path.join(ROOT, 'plugins', 'agathos', '.claude-plugin', 'plugin.json');
const CLI_FROM = path.join(ROOT, 'bin', 'agathos.js');
const CLI_TO = path.join(ROOT, 'plugins', 'agathos', 'cli.js');

// The command line tool of the plugin is bin/agathos.js, looking in lib/ for the files it needs and in the manifest for its version.
function cliText() {
  return fs.readFileSync(CLI_FROM, 'utf8')
    .replace(/require\('\.\.\/core\//g, "require('./lib/")
    .replace("path.join(__dirname, '..', 'package.json')", "path.join(__dirname, '.claude-plugin', 'plugin.json')");
}

function differences() {
  const out = [];
  for (const n of LIB) {
    const from = path.join(ROOT, 'core', `${n}.js`);
    const to = path.join(TO, `${n}.js`);
    let a = null; let b = null;
    try { a = fs.readFileSync(from); } catch (_) { out.push(`${n}.js is missing in core/`); continue; }
    try { b = fs.readFileSync(to); } catch (_) { /* not copied yet */ }
    if (!b || !a.equals(b)) out.push(`${n}.js differs`);
  }
  let cli = null;
  try { cli = fs.readFileSync(CLI_TO, 'utf8'); } catch (_) { /* not made yet */ }
  if (cli !== cliText()) out.push('cli.js differs');
  try {
    const v = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
    if (JSON.parse(fs.readFileSync(MANIFEST, 'utf8')).version !== v) out.push('the version in plugin.json differs');
  } catch (_) { out.push('plugin.json cannot be read'); }
  return out;
}

function sync() {
  fs.mkdirSync(TO, { recursive: true });
  for (const n of LIB) fs.copyFileSync(path.join(ROOT, 'core', `${n}.js`), path.join(TO, `${n}.js`));
  fs.writeFileSync(CLI_TO, cliText());
  const v = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
  const m = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  if (m.version !== v) { m.version = v; fs.writeFileSync(MANIFEST, JSON.stringify(m, null, 2) + '\n'); }
  const market = path.join(ROOT, '.claude-plugin', 'marketplace.json');
  try { const k = JSON.parse(fs.readFileSync(market, 'utf8')); if (k.plugins && k.plugins[0] && k.plugins[0].version !== undefined) { k.plugins[0].version = v; fs.writeFileSync(market, JSON.stringify(k, null, 2) + '\n'); } } catch (_) { /* no marketplace file */ }
}

if (require.main === module) {
  if (process.argv.includes('--check')) {
    const d = differences();
    if (d.length) { console.error(d.join('\n')); process.exit(1); }
    console.log('The copies for the plugin are identical.');
  } else {
    sync();
    console.log(`Copied ${LIB.length} files to plugins/agathos/lib/ and made plugins/agathos/cli.js.`);
  }
}

module.exports = { LIB, differences, sync, cliText };
