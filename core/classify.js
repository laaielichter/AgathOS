'use strict';
// AgathOS - turn raw commands and tool calls into actions from the alphabet.
const C = require('./catalog');

function sensitivePath(text) {
  return C.SENSITIVE_PATHS.some((re) => re.test(text));
}

// A shell command (from a process command line or an agent's Bash tool).
function classifyCommand(cmd) {
  const c = String(cmd || '');
  for (const r of C.COMMAND_RULES) {
    if (r.re.test(c)) {
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

// A tool call from an agent transcript (Claude Code style names, plus MCP tools).
function classifyTool(name, input, cwd) {
  const n = String(name || '');
  const i = input || {};
  const file = i.file_path || i.path || i.notebook_path || '';
  if (n === 'Bash' || n === 'PowerShell' || /shell|terminal|exec_command|run_command/i.test(n)) return classifyCommand(i.command || i.cmd || '');
  if (n === 'WebFetch' || n === 'WebSearch' || /fetch|browse|navigate|search_web|web_search|read_url|scrape|firecrawl|playwright|puppeteer|browser/i.test(n)) return 'READ_UNTRUSTED';
  if (/gmail|email|mail|inbox|slack|discord|telegram|calendar|github.*(issue|comment)|notion/i.test(n) && /(read|get|list|search|fetch)/i.test(n)) return 'READ_UNTRUSTED';
  if (/send|post|upload|publish|create_(issue|comment|message|gist)|webhook|share|push/i.test(n)) return 'EXFIL';
  if (n === 'Read' || /read_file|read_text|view|open_file|get_file/i.test(n)) {
    if (sensitivePath(file)) return 'READ_SENSITIVE';
    if (/[\\/](downloads|temp|tmp)[\\/]/i.test(file)) return 'READ_UNTRUSTED';
    return 'READ_FILE';
  }
  if (n === 'Write' || n === 'Edit' || n === 'MultiEdit' || n === 'NotebookEdit' || /write|edit|create_file|replace|patch/i.test(n)) {
    if (/mcp\.json|claude_desktop_config|settings(\.local)?\.json|config\.toml|\.cursorrules|claude\.md|agents\.md/i.test(file)) return 'MCP_CONFIG_CHANGE';
    if (cwd && file && !String(file).toLowerCase().startsWith(String(cwd).toLowerCase())) return 'WRITE_OUTSIDE';
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

module.exports = { classifyCommand, classifyTool, dangerousFlags, sensitivePath };
