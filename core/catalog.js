'use strict';
// AgathOS - what we know about the AI world on a Windows PC.
// Paths use %USERPROFILE%, %APPDATA% and %LOCALAPPDATA%; util.expand() resolves them.

// ---------- Agents and AI apps ----------
// match: tested against process name (lower case) and command line (lower case).
// root: true when the process itself is "the agent" (its children are its actions).
const AGENTS = [
  { id: 'claude-code', name: 'Claude Code', kind: 'cli', root: true,
    match: (n, c, exe) => (n === 'claude.exe' && !/anthropicclaude|\\claude\\app-/.test(exe)) || /@anthropic-ai[\\/]claude-code|claude-code[\\/]cli\.js/.test(c),
    dirs: ['%USERPROFILE%\\.claude'], version: ['claude', ['--version']], transcripts: 'claude' },
  { id: 'claude-desktop', name: 'Claude Desktop', kind: 'desktop', root: false,
    match: (n, c, exe) => n === 'claude.exe' && /anthropicclaude|\\claude\\app-/.test(exe),
    dirs: ['%APPDATA%\\Claude'] },
  { id: 'codex', name: 'Codex CLI', kind: 'cli', root: true,
    match: (n, c) => n === 'codex.exe' || /@openai[\\/]codex/.test(c),
    dirs: ['%USERPROFILE%\\.codex'], version: ['codex', ['--version']], transcripts: 'codex' },
  { id: 'gemini', name: 'Gemini CLI', kind: 'cli', root: true,
    match: (n, c) => n === 'gemini.exe' || /@google[\\/]gemini-cli/.test(c),
    dirs: ['%USERPROFILE%\\.gemini'], version: ['gemini', ['--version']] },
  { id: 'qwen', name: 'Qwen Code', kind: 'cli', root: true,
    match: (n, c) => n === 'qwen.exe' || /@qwen-code[\\/]qwen-code/.test(c),
    dirs: ['%USERPROFILE%\\.qwen'] },
  { id: 'copilot-cli', name: 'GitHub Copilot CLI', kind: 'cli', root: true,
    match: (n, c) => /@github[\\/]copilot/.test(c),
    dirs: ['%USERPROFILE%\\.copilot'] },
  { id: 'opencode', name: 'opencode', kind: 'cli', root: true,
    match: (n, c) => n === 'opencode.exe' || /[\\/]opencode-ai[\\/]/.test(c),
    dirs: ['%USERPROFILE%\\.config\\opencode'] },
  { id: 'cursor-agent', name: 'Cursor Agent CLI', kind: 'cli', root: true,
    match: (n, c) => n === 'cursor-agent.exe' || /cursor-agent/.test(c), dirs: [] },
  { id: 'aider', name: 'Aider', kind: 'cli', root: true,
    match: (n, c) => n === 'aider.exe' || /[\\/ ]aider(\.exe)?(\s|$)|-m aider/.test(c), dirs: [] },
  { id: 'goose', name: 'Goose', kind: 'cli', root: true,
    match: (n) => n === 'goose.exe', dirs: ['%APPDATA%\\Block\\goose'] },
  { id: 'open-interpreter', name: 'Open Interpreter', kind: 'cli', root: true,
    match: (n, c) => n === 'interpreter.exe' || /-m interpreter/.test(c), dirs: [] },
  { id: 'openclaw', name: 'OpenClaw', kind: 'cli', root: true,
    match: (n, c) => /openclaw/.test(n) || /openclaw/.test(c),
    dirs: ['%USERPROFILE%\\.openclaw'] },
  { id: 'amazon-q', name: 'Amazon Q CLI', kind: 'cli', root: true,
    match: (n, c) => n === 'q.exe' || n === 'qchat.exe' || /\bq(\.exe)? chat\b/.test(c), dirs: ['%USERPROFILE%\\.aws\\amazonq'] },
  { id: 'cline', name: 'Cline', kind: 'extension', root: false, match: () => false,
    dirs: ['%APPDATA%\\Code\\User\\globalStorage\\saoudrizwan.claude-dev', '%USERPROFILE%\\.cline'] },
  { id: 'roo', name: 'Roo Code', kind: 'extension', root: false, match: () => false,
    dirs: ['%APPDATA%\\Code\\User\\globalStorage\\rooveterinaryinc.roo-cline'] },
  { id: 'continue', name: 'Continue', kind: 'extension', root: false, match: () => false,
    dirs: ['%USERPROFILE%\\.continue'] },
  { id: 'copilot', name: 'GitHub Copilot (VS Code)', kind: 'extension', root: false, match: () => false,
    dirs: ['%APPDATA%\\Code\\User\\globalStorage\\github.copilot-chat'] },
  { id: 'cursor', name: 'Cursor', kind: 'ide', root: false,
    match: (n) => n === 'cursor.exe', dirs: ['%USERPROFILE%\\.cursor'], exeVersion: true },
  { id: 'windsurf', name: 'Windsurf', kind: 'ide', root: false,
    match: (n) => n === 'windsurf.exe', dirs: ['%USERPROFILE%\\.codeium\\windsurf'] },
  { id: 'vscode', name: 'VS Code', kind: 'ide', root: false,
    match: (n) => n === 'code.exe', dirs: ['%APPDATA%\\Code\\User'] },
  { id: 'antigravity', name: 'Antigravity', kind: 'ide', root: false,
    match: (n) => n === 'antigravity.exe', dirs: ['%USERPROFILE%\\.antigravity', '%APPDATA%\\Antigravity'] },
  { id: 'ollama', name: 'Ollama', kind: 'server', root: false,
    match: (n) => n === 'ollama.exe' || n === 'ollama app.exe', dirs: ['%USERPROFILE%\\.ollama'], version: ['ollama', ['--version']] },
  { id: 'lmstudio', name: 'LM Studio', kind: 'server', root: false,
    match: (n) => n === 'lm studio.exe' || n === 'lms.exe', dirs: ['%USERPROFILE%\\.lmstudio', '%USERPROFILE%\\.cache\\lm-studio'] },
  { id: 'gpt4all', name: 'GPT4All', kind: 'server', root: false,
    match: (n) => n === 'chat.exe' && false, dirs: ['%LOCALAPPDATA%\\nomic.ai'] },
  { id: 'jan', name: 'Jan', kind: 'server', root: false,
    match: (n) => n === 'jan.exe', dirs: ['%APPDATA%\\Jan'] },
];

// Parents that normally start agents. Anything else is worth a look
// (the Nx "s1ngularity" malware started AI CLIs from an npm install script).
const NORMAL_LAUNCHERS = new Set([
  'cmd.exe', 'powershell.exe', 'pwsh.exe', 'windowsterminal.exe', 'openconsole.exe', 'conhost.exe', 'explorer.exe',
  'code.exe', 'cursor.exe', 'windsurf.exe', 'antigravity.exe', 'bash.exe', 'wsl.exe', 'wslhost.exe', 'mintty.exe',
  'alacritty.exe', 'wezterm-gui.exe', 'tabby.exe', 'hyper.exe', 'warp.exe', 'idea64.exe', 'pycharm64.exe',
  'webstorm64.exe', 'claude.exe', 'node.exe', 'sh.exe', 'zsh.exe', 'fish.exe', 'nu.exe', 'agathos.exe', 'electron.exe',
]);

// ---------- MCP configuration files ----------
// format: json (mcpServers / servers / mcp.servers) or toml (codex [mcp_servers.x])
const MCP_CONFIGS = [
  { app: 'Claude Desktop', path: '%APPDATA%\\Claude\\claude_desktop_config.json', format: 'json' },
  { app: 'Claude Code', path: '%USERPROFILE%\\.claude.json', format: 'json' },
  { app: 'Claude Code', path: '%USERPROFILE%\\.claude\\settings.json', format: 'json' },
  { app: 'Cursor', path: '%USERPROFILE%\\.cursor\\mcp.json', format: 'json' },
  { app: 'Windsurf', path: '%USERPROFILE%\\.codeium\\windsurf\\mcp_config.json', format: 'json' },
  { app: 'VS Code', path: '%APPDATA%\\Code\\User\\mcp.json', format: 'json' },
  { app: 'VS Code', path: '%APPDATA%\\Code\\User\\settings.json', format: 'json' },
  { app: 'Cline', path: '%APPDATA%\\Code\\User\\globalStorage\\saoudrizwan.claude-dev\\settings\\cline_mcp_settings.json', format: 'json' },
  { app: 'Roo Code', path: '%APPDATA%\\Code\\User\\globalStorage\\rooveterinaryinc.roo-cline\\settings\\mcp_settings.json', format: 'json' },
  { app: 'Codex CLI', path: '%USERPROFILE%\\.codex\\config.toml', format: 'toml' },
  { app: 'Gemini CLI', path: '%USERPROFILE%\\.gemini\\settings.json', format: 'json' },
  { app: 'Qwen Code', path: '%USERPROFILE%\\.qwen\\settings.json', format: 'json' },
  { app: 'Continue', path: '%USERPROFILE%\\.continue\\config.json', format: 'json' },
  { app: 'Antigravity', path: '%USERPROFILE%\\.gemini\\antigravity\\mcp_config.json', format: 'json' },
  { app: 'LM Studio', path: '%USERPROFILE%\\.lmstudio\\mcp.json', format: 'json' },
];

// Settings that switch an agent into "everything allowed" mode.
const RISKY_CONFIG_KEYS = [
  { re: /"chat\.tools\.autoApprove"\s*:\s*true/, key: 'chat.tools.autoApprove' },
  { re: /"chat\.tools\.global\.autoApprove"\s*:\s*true/, key: 'chat.tools.global.autoApprove' },
  { re: /"defaultMode"\s*:\s*"bypassPermissions"/, key: 'defaultMode: bypassPermissions' },
  { re: /"dangerouslySkipPermissions"\s*:\s*true/, key: 'dangerouslySkipPermissions' },
  { re: /approval_policy\s*=\s*"never"/, key: 'approval_policy = "never"' },
  { re: /sandbox_mode\s*=\s*"danger-full-access"/, key: 'sandbox_mode = "danger-full-access"' },
  { re: /"autoAccept"\s*:\s*true/, key: 'autoAccept' },
  { re: /"yolo"\s*:\s*true/i, key: 'yolo' },
  { re: /"alwaysAllow"\s*:\s*\[\s*"[^"]/, key: 'alwaysAllow' },
];

// Environment overrides that send an agent's traffic (and API key) elsewhere.
const BASE_URL_VARS = ['ANTHROPIC_BASE_URL', 'OPENAI_BASE_URL', 'OPENAI_API_BASE', 'GOOGLE_GEMINI_BASE_URL', 'GEMINI_BASE_URL'];
const OFFICIAL_HOSTS = /(^|\.)(anthropic\.com|openai\.com|googleapis\.com|azure\.com|openai\.azure\.com|amazonaws\.com|localhost|127\.0\.0\.1)$/i;

// ---------- Instruction files (read by agents as orders) ----------
const INSTRUCTION_FILES = new Set(['claude.md', 'agents.md', 'gemini.md', 'qwen.md', '.cursorrules', '.windsurfrules',
  '.clinerules', 'copilot-instructions.md', 'skill.md', 'conventions.md', '.goosehints', 'agent.md']);
const INSTRUCTION_DIR_HINTS = [/[\\/]\.cursor[\\/]rules[\\/]/i, /[\\/]\.clinerules[\\/]/i, /[\\/]\.roo[\\/]rules/i,
  /[\\/]\.claude[\\/](commands|agents|skills)[\\/]/i, /[\\/]\.github[\\/]instructions[\\/]/i];
const SKILL_DIRS = ['%USERPROFILE%\\.claude\\skills', '%USERPROFILE%\\.openclaw\\skills', '%USERPROFILE%\\.agents\\skills',
  '%USERPROFILE%\\.codex\\skills', '%USERPROFILE%\\.claude\\plugins'];

// ---------- Local AI servers ----------
const AI_PORTS = {
  11434: 'Ollama', 1234: 'LM Studio', 8080: 'Open WebUI / llama.cpp', 3000: 'Open WebUI', 18789: 'OpenClaw',
  7860: 'Gradio / text-generation-webui', 8188: 'ComfyUI', 5000: 'KoboldCpp / text-generation-webui', 5001: 'KoboldCpp',
  8000: 'vLLM / LocalAI', 4891: 'GPT4All', 1337: 'Jan', 3001: 'AnythingLLM', 6333: 'Qdrant', 8001: 'TGI',
};
const AI_SERVER_PROCS = /ollama|lm studio|lms\.exe|llama-server|koboldcpp|text-generation|vllm|localai|open-webui|comfyui|gpt4all|jan\.exe|anythingllm|openclaw|python|node|uvicorn/i;

// ---------- Known bad MCP packages / versions ----------
// Only entries backed by public research. Extend through signed community rule updates later.
const KNOWN_BAD_PACKAGES = [
  { name: 'postmark-mcp', versions: ['1.0.16', '1.0.17', '1.0.18'], anyVersionRisk: true,
    why: 'BCC to an attacker address (Snyk, Sep 2025)' },
];

// Minimum versions with a verified fix. Unknown fixes are left out on purpose.
const MIN_VERSIONS = {
  gemini: { min: '0.1.14', cve: 'GEMINI.md injection (Jul 2025)' },
  cursor: { min: '3.0.0', cve: 'CVE-2026-50548 / CVE-2026-50549' },
  'open-webui': { min: '0.6.35', cve: 'CVE-2025-64496' },
};

// ---------- Commands ----------
// Dangerous start flags. These turned AI CLIs into tools for the Nx malware.
const DANGEROUS_FLAGS = ['--dangerously-skip-permissions', '--yolo', '--trust-all-tools', '--dangerously-bypass-approvals-and-sandbox',
  '--full-auto', '--no-confirm', '--yes-always', '--auto-approve', '--allow-all-tools', '--approval-mode yolo', '--approval-mode=yolo'];

// Sensitive locations: an agent reading these is "touching private data".
const SENSITIVE_PATHS = [
  /[\\/]\.ssh[\\/]/i, /[\\/]\.aws[\\/]credentials/i, /[\\/]\.gnupg[\\/]/i, /[\\/]\.kube[\\/]config/i, /[\\/]\.docker[\\/]config\.json/i,
  /[\\/]\.npmrc$/i, /[\\/]\.pypirc$/i, /[\\/]\.git-credentials$/i, /[\\/]\.netrc$/i, /\.env(\.[a-z]+)?$/i, /[\\/]\.config[\\/]gh[\\/]hosts\.yml/i,
  /google[\\/]chrome[\\/]user data/i, /microsoft[\\/]edge[\\/]user data/i, /mozilla[\\/]firefox[\\/]profiles/i, /brave-browser[\\/]user data/i,
  /login data/i, /[\\/]cookies$/i, /wallet/i, /metamask/i, /exodus/i, /electrum/i, /phantom/i, /keepass|\.kdbx$/i, /1password|bitwarden/i,
  /[\\/]microsoft[\\/]credentials[\\/]/i, /[\\/]microsoft[\\/]protect[\\/]/i, /id_rsa|id_ed25519|id_ecdsa/i, /\.pem$|\.pfx$|\.p12$|\.key$/i,
];

// Classify one command line into an action from the alphabet.
// Order matters: the first match wins, most severe first.
const COMMAND_RULES = [
  { action: 'DISABLE_SECURITY', re: /set-mppreference\s+-disable|add-mppreference\s+-exclusion|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off|bcdedit|vssadmin\s+delete|wbadmin\s+delete|reg\s+add\s+.*\\windows defender/i },
  { action: 'DELETE_MANY', re: /\brmdir\s+\/s|\brd\s+\/s|\bdel\s+(\/[a-z]\s+)*\/s|remove-item\b.*-recurse|\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r|format(\.com)?\s+[a-z]:|cipher\s+\/w|shred\b|diskpart|git\s+clean\s+-[a-z]*f[a-z]*d|git\s+reset\s+--hard|terraform\s+destroy|drop\s+(database|table)/i },
  { action: 'PERSISTENCE', re: /schtasks\s+\/create|reg\s+add\s+.*\\currentversion\\run|new-itemproperty\s+.*\\currentversion\\run|register-scheduledtask|\\start menu\\programs\\startup|sc\.exe\s+create|new-service\b/i },
  { action: 'EXEC_DOWNLOADED', re: /(iwr|invoke-webrequest|irm|invoke-restmethod|curl|wget)\b[^|]*\|\s*(iex|invoke-expression|bash|sh|python|node)|iex\s*\(\s*(new-object\s+net\.webclient|iwr|irm)|certutil\s+.*-urlcache|bitsadmin\s+\/transfer|mshta\s+http|rundll32\s+.*http|powershell\s+.*-enc(odedcommand)?\s/i },
  { action: 'CREDENTIAL_ACCESS', re: /cmdkey\s+\/list|vaultcmd|mimikatz|lsass|get-storedcredential|trufflehog|gitleaks|findstr\s+.*(password|api_key|secret)|select-string\s+.*(password|api_key|secret)|dpapi|\bsekurlsa\b/i },
  { action: 'GIT_PUSH', re: /git\s+push\b/i },
  { action: 'EXFIL', re: /(curl|wget)\s+.*(-d|--data|-F|--upload-file|-T)\s|invoke-(webrequest|restmethod)\s+.*-method\s+(post|put)|scp\s|rclone\s|ftp\s|nc(\.exe)?\s+-|ncat\s|send-mailmessage|discord(app)?\.com\/api\/webhooks|api\.telegram\.org|webhook\.site|pastebin|transfer\.sh|ngrok/i },
  { action: 'INSTALL_PKG', re: /\b(npm|pnpm|yarn|bun)\s+(i|install|add)\b|\bpip3?\s+install\b|\buv\s+(pip\s+install|add)\b|\bnpx\s+-y\b|\bwinget\s+install\b|\bchoco\s+install\b|\bscoop\s+install\b|\bcargo\s+install\b/i },
  { action: 'NET_FETCH', re: /\b(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b|git\s+clone\b/i },
  { action: 'ENUMERATE', re: /dir\s+.*\/s\b|get-childitem\b.*-recurse|\bfind\s+[~\/\\]|\btree\s+[a-z]:|where\s+\/r\b|\bls\s+-[a-z]*r/i },
  { action: 'TEST_RUN', re: /\b(pytest|jest|vitest|mocha|go\s+test|cargo\s+test|dotnet\s+test|npm\s+(run\s+)?test|pnpm\s+(run\s+)?test|yarn\s+test|bun\s+test|phpunit|rspec|ctest|gradle\s+test|mvn\s+test|godot\s+.*--test|unittest)\b/i },
  { action: 'EXEC_SHELL', re: /./ },
];

// The action alphabet. sev: 0..1 (how bad on its own). Names are translated in the UI.
const ACTIONS = {
  READ_FILE: { sev: 0.02 }, WRITE_FILE: { sev: 0.05 }, TEST_RUN: { sev: 0.02 }, EXEC_SHELL: { sev: 0.08 },
  ENUMERATE: { sev: 0.2 }, READ_UNTRUSTED: { sev: 0.2 }, NET_FETCH: { sev: 0.2 }, INSTALL_PKG: { sev: 0.25 },
  WRITE_OUTSIDE: { sev: 0.3 }, READ_SENSITIVE: { sev: 0.55 }, MCP_CONFIG_CHANGE: { sev: 0.6 }, GIT_PUSH: { sev: 0.35 },
  NET_NEW: { sev: 0.45 }, EXFIL: { sev: 0.85 }, CREDENTIAL_ACCESS: { sev: 0.8 }, EXEC_DOWNLOADED: { sev: 0.85 },
  PERSISTENCE: { sev: 0.85 }, DELETE_MANY: { sev: 0.9 }, DISABLE_SECURITY: { sev: 0.95 },
};

// Which actions set the three "lethal trifecta" labels.
const LABEL_OF = {
  untrusted: new Set(['READ_UNTRUSTED', 'NET_FETCH']),
  private: new Set(['READ_SENSITIVE', 'CREDENTIAL_ACCESS']),
  exit: new Set(['EXFIL', 'NET_NEW', 'GIT_PUSH']),
};

// Attack chains (kill-chain style). A warning fires when only the last stage is missing.
const CHAINS = [
  { id: 'exfil', stages: [['ENUMERATE', 'READ_UNTRUSTED', 'NET_FETCH'], ['READ_SENSITIVE', 'CREDENTIAL_ACCESS'], ['EXFIL', 'NET_NEW']] },
  { id: 'hijack', stages: [['READ_UNTRUSTED', 'NET_FETCH'], ['MCP_CONFIG_CHANGE', 'DISABLE_SECURITY'], ['EXEC_DOWNLOADED', 'EXFIL', 'PERSISTENCE']] },
  { id: 'destroy', stages: [['ENUMERATE'], ['DELETE_MANY']] },
  { id: 'implant', stages: [['NET_FETCH', 'INSTALL_PKG'], ['EXEC_DOWNLOADED'], ['PERSISTENCE']] },
  { id: 'secrets', stages: [['ENUMERATE'], ['CREDENTIAL_ACCESS', 'READ_SENSITIVE'], ['NET_NEW', 'EXFIL', 'GIT_PUSH']] },
];

// Hard rules: always on, never learned away. Score floor when they fire.
const HARD_FLOOR = {
  DISABLE_SECURITY: 92, PERSISTENCE: 85, EXEC_DOWNLOADED: 85, CREDENTIAL_ACCESS: 82, DELETE_MANY: 88, EXFIL: 80,
};

// Text in instruction files that reads like an attack.
const INJECTION_PHRASES = [
  /ignore (all |any )?(previous|prior|above) (instructions|rules)/i, /disregard (all |any )?(previous|prior) (instructions|rules)/i,
  /do not (tell|inform|mention (this )?to) the user/i, /don'?t (tell|mention|show) (this )?(to )?the user/i, /without (telling|asking|informing) the user/i,
  /the user (must|should) not (know|see)/i, /negeer (alle )?(vorige|eerdere) instructies/i, /zeg (dit )?niet tegen de gebruiker/i,
  /(curl|wget|iwr|invoke-webrequest)[^\n]{0,120}\|\s*(bash|sh|iex|powershell|python)/i, /send (the )?(contents|keys|secrets|credentials|\.env|ssh)/i,
  /(exfiltrate|upload) (all )?(the )?(secrets|keys|credentials|files)/i, /base64 -d|frombase64string/i,
  /(read|cat|type|get-content)\s+[^\n]{0,40}(\.ssh|id_rsa|\.env|credentials)/i, /webhook\.site|pastebin\.com|transfer\.sh|ngrok\.io/i,
];

module.exports = {
  AGENTS, NORMAL_LAUNCHERS, MCP_CONFIGS, RISKY_CONFIG_KEYS, BASE_URL_VARS, OFFICIAL_HOSTS, INSTRUCTION_FILES,
  INSTRUCTION_DIR_HINTS, SKILL_DIRS, AI_PORTS, AI_SERVER_PROCS, KNOWN_BAD_PACKAGES, MIN_VERSIONS, DANGEROUS_FLAGS,
  SENSITIVE_PATHS, COMMAND_RULES, ACTIONS, LABEL_OF, CHAINS, HARD_FLOOR, INJECTION_PHRASES,
};
