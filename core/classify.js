'use strict';
// AgathOS - turn raw commands and tool calls into actions from the alphabet.
const C = require('./catalog');

// Decide whether a written path lies inside the working folder from the TEXT of
// the two paths alone: nothing is read from disk and no links are followed (#61).
// A plain string prefix check is wrong in both directions — `/home/me/proj2` starts
// with `/home/me/proj`, and a relative `src/a.js` starts with no absolute cwd at
// all. Both `\` and `/` are accepted regardless of the host OS, and `.` / `..`
// are resolved lexically so a Windows path is understood on Linux and vice versa.
function partsOf(text) {
  const s = String(text || '').replace(/\\/g, '/');
  const drive = /^([A-Za-z]:)(\/|$)/.exec(s);
  const windows = !!drive || s.startsWith('//');
  let prefix = '';
  let rest = s;
  if (drive) { prefix = drive[1].toLowerCase() + '/'; rest = s.slice(drive[1].length); }
  else if (s.startsWith('//')) { prefix = '//'; rest = s.slice(2); }
  else if (s.startsWith('/')) { prefix = '/'; rest = s.slice(1); }
  const parts = [];
  let escaped = false;
  for (const segment of rest.split('/')) {
    if (!segment || segment === '.') continue;
    if (segment === '..') {
      // `..` above the root of an absolute path stays at the root; in a relative
      // path it climbs out of the working folder, which is a write outside (#61).
      if (parts.length) parts.pop();
      else if (!prefix) escaped = true;
      continue;
    }
    parts.push(windows ? segment.toLowerCase() : segment);
  }
  return { prefix, parts, absolute: !!prefix, escaped, windows };
}

// A path that starts with `~` (or a shell spelling of the home folder) points
// somewhere we cannot resolve from the text alone. MCP filesystem tools accept
// those paths, and they are exactly the writes WRITE_OUTSIDE is there to weigh
// heavily (#61). main treats them as outside; keep the same answer here.
function homeReference(text) {
  const s = String(text || '');
  return /^~/.test(s) // ~, ~/…, ~\…, ~user/…
      || /^(?:\$HOME|\$\{HOME\}|%USERPROFILE%)(?=$|[\\/])/i.test(s);
}

function insideProject(file, cwd) {
  if (homeReference(file)) return false;
  if (!cwd || !file) return true; // as today: without a working folder it is a plain write
  const c = partsOf(cwd);
  const f = partsOf(file);
  // A relative path belongs to the working folder by definition, unless `..`
  // climbs above it.
  if (!f.absolute) return !f.escaped;
  // A Windows path rooted at `\` has no drive letter of its own; read it as the
  // drive of the working folder it is being compared with.
  if (c.windows && !f.windows && f.prefix === '/') {
    f.prefix = c.prefix;
    f.parts = f.parts.map((x) => x.toLowerCase());
  }
  if (f.prefix !== c.prefix || f.parts.length < c.parts.length) return false;
  // Compare segments, not characters: `/home/me/proj2` cannot match `/home/me/proj`.
  return c.parts.every((segment, i) => f.parts[i] === segment);
}

function sensitivePath(text) {
  return C.SENSITIVE_PATHS.some((re) => re.test(text));
}

// Files that steer an AI program: instruction files and MCP config files. Both
// lists already live in catalog.js, so derive the match from them instead of
// keeping a second long regex (#13).
//
// The distinctive names (GEMINI.md, .clinerules, .claude.json,
// mcp_config.json, ...) are enough on their own. The generic ones
// (config.json, settings.json, mcp.json, config.toml) only count inside the
// folder catalog.js names for that app: asking about every config.json in a
// project would only be noise, as the issue points out for Continue.
const GENERIC_CONFIG_NAMES = new Set([
  'config.json', 'settings.json', 'mcp.json', 'config.toml', 'user-settings.json',
]);
const slashPath = (p) => String(p || '').replace(/\\/g, '/').toLowerCase();
const AGENT_SETTING_NAMES = new Set([
  ...C.INSTRUCTION_FILES,
  ...C.MCP_CONFIGS.map(({ path }) => slashPath(path).split('/').pop())
    .filter((name) => name && !GENERIC_CONFIG_NAMES.has(name)),
]);
// "%USERPROFILE%\\.codeium\\windsurf\\mcp_config.json" -> ".codeium/windsurf/mcp_config.json".
// Dropping the environment prefix makes the same suffix work for a Windows path
// (C:\Users\me\.codeium\...) and a POSIX one (/Users/me/.codeium/...).
const AGENT_SETTING_SUFFIXES = [...new Set(C.MCP_CONFIGS.map(({ path }) => {
  const p = slashPath(path).replace(/^%[a-z0-9_]+%\//, '');
  return p.includes('/') ? p : '';
}).filter(Boolean))];
function agentSettingsFile(file) {
  const p = slashPath(file);
  if (AGENT_SETTING_NAMES.has(p.split('/').pop())) return true;
  return AGENT_SETTING_SUFFIXES.some((s) => p === s || p.endsWith('/' + s));
}

// A shell command (from a process command line or an agent's Bash tool).
function classifyCommand(cmd) {
  const c = String(cmd || '');
  for (const r of C.COMMAND_RULES) {
    // A rule is a regular expression, or a function where one expression cannot say it (#31, #32).
    if (r.test ? r.test(c) : r.re.test(c)) {
      // Reading secrets through a plain command (type, cat, Get-Content) counts as private access.
      if ((r.action === 'EXEC_SHELL' || r.action === 'ENUMERATE') && sensitivePath(c)) return 'READ_SENSITIVE';
      return r.action;
    }
  }
  return 'EXEC_SHELL';
}

function dangerousFlags(cmd) {
  const c = String(cmd || '').toLowerCase();
  return C.DANGEROUS_FLAGS.filter((f) => c.includes(f));
}

// The text values of a tool call (paths and names), flattened and cut: what a copy tool is told to copy and where to.
function textsOf(v, depth = 0, out = []) {
  if (out.join('').length > 4000 || depth > 3) return out;
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) for (const x of v.slice(0, 20)) textsOf(x, depth + 1, out);
  else if (v && typeof v === 'object') for (const x of Object.values(v).slice(0, 20)) textsOf(x, depth + 1, out);
  return out;
}

// A tool that runs a command line. For these the action is read from the command itself; for other tools it is a guess from the name.
const isShellTool = (name) => { const n = String(name || ''); return n === 'Bash' || n === 'PowerShell' || /shell|terminal|exec_command|run_command/i.test(n); };

// A tool call from an agent transcript (Claude Code style names, plus MCP tools).
function classifyTool(name, input, cwd) {
  const n = String(name || '');
  const i = input || {};
  const file = i.file_path || i.path || i.notebook_path || '';
  if (isShellTool(n)) return classifyCommand(i.command || i.cmd || '');
  if (n === 'WebFetch' || n === 'WebSearch' || /fetch|browse|navigate|search_web|web_search|read_url|scrape|firecrawl|playwright|puppeteer|browser/i.test(n)) return 'READ_UNTRUSTED';
  if (/gmail|email|mail|inbox|slack|discord|telegram|calendar|github.*(issue|comment)|notion/i.test(n) && /(read|get|list|search|fetch)/i.test(n)) return 'READ_UNTRUSTED';
  if (/send|post|upload|publish|create_(issue|comment|message|gist)|webhook|share|push/i.test(n)) return 'EXFIL';
  if (n === 'Read' || /read_file|read_text|view|open_file|get_file/i.test(n)) {
    if (sensitivePath(file)) return 'READ_SENSITIVE';
    if (/[\\/](downloads|temp|tmp)[\\/]/i.test(file)) return 'READ_UNTRUSTED';
    return 'READ_FILE';
  }
  if (n === 'Write' || n === 'Edit' || n === 'MultiEdit' || n === 'NotebookEdit' || /write|edit|create_file|replace|patch/i.test(n)) {
    if (/mcp\.json|claude_desktop_config|settings(\.local)?\.json|config\.toml|\.cursorrules|claude\.md|agents\.md/i.test(file)
        || agentSettingsFile(file)) return 'MCP_CONFIG_CHANGE';
    if (!insideProject(file, cwd)) return 'WRITE_OUTSIDE';
    return 'WRITE_FILE';
  }
  if (n === 'Glob' || n === 'Grep' || /list_dir|search_files|find_files|directory_tree/i.test(n)) {
    return sensitivePath(JSON.stringify(i)) ? 'READ_SENSITIVE' : 'READ_FILE';
  }
  // A tool that copies or moves things: a model, or the home folder of an agent, is a copy of AI itself.
  if (/(^|[_.\s-])(copy|cp|move|mv|clone|duplicate|backup|archive|zip|rsync)([_.\s-]|$)/i.test(n)) {
    const text = textsOf(i).join('\n').slice(0, 4000);
    if (C.AGENT_HOME_RE.test(text)) return 'SELF_COPY';
    if (C.MODEL_REF_RE.test(text)) return 'COPY_MODEL';
  }
  if (/delete|remove|rm_|unlink/i.test(n)) return 'DELETE_MANY';
  return 'EXEC_SHELL';
}

module.exports = { classifyCommand, classifyTool, isShellTool, dangerousFlags, sensitivePath, insideProject };
