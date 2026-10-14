'use strict';
// AgathOS - AI links: which AI does each program talk to, and is that link what it should be?
//
// A "link" is the place where a program sends its prompts (and its key): the address of a language
// model, an MCP server, a local model server, or another agent. Attacks on AI often start there:
// a base address that was swapped for a look-alike, a tunnel to a stranger's machine, an MCP server
// that is itself an agent. AgathOS reads the settings files and variables that hold such addresses
// (text only, nothing is run, nothing is sent) and judges each address by its name alone:
//   * the official address of a known provider                      -> calm
//   * this PC, or a server on your own network                      -> calm once you approved it
//   * a hosting platform or an unknown server                       -> attention until you approve it
//   * a look-alike of a provider (api.openai.com.evil.example)      -> danger
//   * a tunnel (ngrok, trycloudflare) or a catch-all site           -> danger
// An approved link that later points somewhere else is a danger again.
const path = require('path');
const nodeUrl = require('url');
const U = require('./util');
const C = require('./catalog');

// ---------- who is who ----------
// Registrable domains that belong to one AI provider only. Generic clouds (amazonaws.com, azure.com,
// googleapis.com, cloudflare.com ...) are not in this list: anybody can put a server there.
const OFFICIAL = {
  'anthropic.com': 'Anthropic', 'claude.ai': 'Anthropic', 'claude.com': 'Anthropic',
  'openai.com': 'OpenAI', 'chatgpt.com': 'OpenAI', 'x.ai': 'xAI', 'grok.com': 'xAI',
  'mistral.ai': 'Mistral', 'groq.com': 'Groq', 'deepseek.com': 'DeepSeek', 'together.xyz': 'Together', 'together.ai': 'Together',
  'openrouter.ai': 'OpenRouter', 'perplexity.ai': 'Perplexity', 'cohere.ai': 'Cohere', 'cohere.com': 'Cohere', 'fireworks.ai': 'Fireworks',
  'cerebras.ai': 'Cerebras', 'huggingface.co': 'Hugging Face', 'hf.co': 'Hugging Face', 'moonshot.ai': 'Moonshot', 'moonshot.cn': 'Moonshot',
  'z.ai': 'Z.ai', 'bigmodel.cn': 'Zhipu', 'replicate.com': 'Replicate', 'ollama.com': 'Ollama', 'githubcopilot.com': 'GitHub Copilot',
  'nvidia.com': 'NVIDIA', 'sambanova.ai': 'SambaNova', 'novita.ai': 'Novita', 'cursor.sh': 'Cursor', 'cursor.com': 'Cursor',
  'codeium.com': 'Windsurf', 'windsurf.com': 'Windsurf', 'ampcode.com': 'Amp', 'sourcegraph.com': 'Sourcegraph', 'llama.com': 'Meta Llama',
  'minimax.io': 'MiniMax', 'minimaxi.com': 'MiniMax', 'minimax.chat': 'MiniMax', 'siliconflow.cn': 'SiliconFlow', 'siliconflow.com': 'SiliconFlow', 'lmstudio.ai': 'LM Studio',
  'deepinfra.com': 'DeepInfra', 'hyperbolic.xyz': 'Hyperbolic', 'nebius.com': 'Nebius', 'lambda.ai': 'Lambda', 'friendli.ai': 'FriendliAI', 'ai21.com': 'AI21',
  'voyageai.com': 'Voyage AI', 'jina.ai': 'Jina', 'baseten.co': 'Baseten', 'parasail.io': 'Parasail', 'featherless.ai': 'Featherless', 'chutes.ai': 'Chutes',
  'stepfun.com': 'StepFun', 'volces.com': 'Volcengine', 'baidubce.com': 'Baidu', 'lingyiwanwu.com': '01.AI', 'kimi.com': 'Moonshot', 'kluster.ai': 'Kluster',
};
// Addresses on a big cloud that are the AI service of that cloud itself.
const CLOUD_API = [
  { re: /(^|\.)generativelanguage\.googleapis\.com$/, name: 'Google' },
  { re: /(^|\.)([a-z0-9-]+-)?aiplatform\.googleapis\.com$/, name: 'Google Vertex AI' },
  { re: /^bedrock(-runtime|-agent|-agent-runtime)?(-fips)?\.[a-z0-9-]+\.amazonaws\.com$/, name: 'Amazon Bedrock' },
  { re: /^runtime\.sagemaker\.[a-z0-9-]+\.amazonaws\.com$/, name: 'Amazon SageMaker' },
  { re: /\.openai\.azure\.com$/, name: 'Azure OpenAI' },
  { re: /\.(cognitiveservices|services\.ai)\.azure\.com$/, name: 'Azure AI' },
  { re: /\.inference\.ai\.azure\.com$/, name: 'Azure AI' },
  { re: /^dashscope(-intl|-us)?\.aliyuncs\.com$/, name: 'Alibaba Cloud' },
  { re: /^gateway\.ai\.cloudflare\.com$/, name: 'Cloudflare AI Gateway' },
  { re: /^models\.github\.ai$/, name: 'GitHub Models' },
  { re: /^copilot-proxy\.githubusercontent\.com$/, name: 'GitHub Copilot' },
];
// The default provider of a program, for the map of who talks to whom.
const AGENT_PROVIDER = {
  'claude-code': 'Anthropic', 'claude-desktop': 'Anthropic', codex: 'OpenAI', chatgpt: 'OpenAI', gemini: 'Google', antigravity: 'Google',
  qwen: 'Alibaba Cloud', 'copilot-cli': 'GitHub Copilot', copilot: 'GitHub Copilot', grok: 'xAI', 'grok-bot': 'xAI', 'cursor-agent': 'Cursor',
  cursor: 'Cursor', windsurf: 'Windsurf', amp: 'Amp', kimi: 'Moonshot', 'mistral-vibe': 'Mistral', comet: 'Perplexity',
  kiro: 'Amazon', 'kiro-cli': 'Amazon', 'amazon-q': 'Amazon',
};
// Programs whose job is to run models on this PC.
const LOCAL_SERVERS = new Set(['ollama', 'lmstudio', 'gpt4all', 'jan', 'llamacpp', 'koboldcpp', 'msty', 'anythingllm']);

// Words an attacker puts in an address to look like a provider.
const BRANDS = ['anthropic', 'claude', 'openai', 'chatgpt', 'gemini', 'mistral', 'deepseek', 'huggingface', 'ollama', 'openrouter', 'perplexity',
  'cohere', 'copilot', 'cursor', 'together', 'fireworks', 'cerebras', 'moonshot', 'replicate', 'nvidia', 'windsurf', 'codeium', 'groq', 'grok', 'codex'];
const BRAND_NAME = { anthropic: 'Anthropic', claude: 'Anthropic', openai: 'OpenAI', chatgpt: 'OpenAI', gemini: 'Google Gemini', mistral: 'Mistral', deepseek: 'DeepSeek',
  huggingface: 'Hugging Face', ollama: 'Ollama', openrouter: 'OpenRouter', perplexity: 'Perplexity', cohere: 'Cohere', copilot: 'GitHub Copilot', cursor: 'Cursor',
  together: 'Together', fireworks: 'Fireworks', cerebras: 'Cerebras', moonshot: 'Moonshot', replicate: 'Replicate', nvidia: 'NVIDIA', windsurf: 'Windsurf',
  codeium: 'Windsurf', groq: 'Groq', grok: 'xAI', codex: 'OpenAI' };

// Machines that anyone on the internet can reach through a tunnel to somebody's computer.
const TUNNEL = /(^|\.)(ngrok(-free)?\.(io|app|dev|com)|trycloudflare\.com|loca\.lt|localtunnel\.me|serveo\.net|pinggy\.(io|link)|lhr\.life|localhost\.run|tunnelto\.dev|devtunnels\.ms|playit\.gg|zrok\.io|bore\.pub|telebit\.(cloud|io)|lt\.vc|burrow\.io|expose\.dev|sharedwithexpose\.com|portmap\.io|ngrok-free\.dev)$/i;
// Sites that only collect what is sent to them.
const CATCHALL = /(^|\.)(webhook\.site|requestbin\.(com|net)|pipedream\.net|interact\.sh|oast\.(fun|live|pro|site|online|me)|burpcollaborator\.net|canarytokens\.(com|org)|hookbin\.com|beeceptor\.com|requestcatcher\.com|mockbin\.(io|org)|postb\.in|ptsv2\.com|webhook\.lol)$/i;
// Platforms where anybody can run a server: not bad, but not a provider either.
const HOSTING = /(^|\.)(amazonaws\.com|cloudfront\.net|azurewebsites\.net|azure-api\.net|cloudapp\.azure\.com|windows\.net|workers\.dev|pages\.dev|vercel\.app|netlify\.app|onrender\.com|fly\.dev|herokuapp\.com|railway\.app|github\.io|githubusercontent\.com|hf\.space|replit\.(app|dev)|repl\.co|glitch\.me|modal\.run|runpod\.(io|net)|vast\.ai|ondigitalocean\.app|digitaloceanspaces\.com|koyeb\.app|deno\.(dev|net)|supabase\.co|firebaseapp\.com|web\.app|appspot\.com|run\.app|cloudfunctions\.net|googleusercontent\.com|storage\.googleapis\.com|cloudflare\.com|gitpod\.io|codespaces\.dev|github\.dev|app\.github\.dev)$/i;

// ---------- small helpers ----------
const MULTI_TLD = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.jp', 'ne.jp', 'or.jp', 'com.cn', 'net.cn', 'org.cn',
  'com.br', 'com.tr', 'co.in', 'co.kr', 'co.nz', 'co.za', 'com.mx', 'com.sg', 'com.hk', 'com.tw', 'co.id', 'com.ua', 'com.ar', 'com.pl']);
function registrable(host) {
  const l = String(host).split('.');
  if (l.length <= 2) return l.join('.');
  const last2 = l.slice(-2).join('.');
  return MULTI_TLD.has(last2) ? l.slice(-3).join('.') : last2;
}

function editDistance(a, b) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > 3) return 9;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[b.length];
}

const isIPv4 = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) && h.split('.').every((n) => Number(n) <= 255);
// ::ffff:7f00:1 is 127.0.0.1 written the long way: the part after ::ffff: is the address.
function mapped(h) {
  const m = /^(?:0:0:0:0:0:|::)ffff:(?:(\d{1,3}(?:\.\d{1,3}){3})|([0-9a-f]{1,4}):([0-9a-f]{1,4}))$/i.exec(h);
  if (!m) return h;
  if (m[1]) return m[1];
  const a = parseInt(m[2], 16);
  const b = parseInt(m[3], 16);
  return `${a >> 8}.${a & 255}.${b >> 8}.${b & 255}`;
}
function isLocalHost(h) {
  return h === 'localhost' || h.endsWith('.localhost') || h === '::1' || h === '0:0:0:0:0:0:0:1' || h === '::' || h === '0.0.0.0' ||
    (h.startsWith('127.') && isIPv4(h)) || h === 'host.docker.internal' || h === 'host.containers.internal';
}
function isLan(h) {
  if (isIPv4(h)) {
    const [a, b] = h.split('.').map(Number);
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
  }
  if (h.includes(':')) return /^(fc|fd|fe[89ab])/i.test(h);
  return /\.(local|lan|home|internal|home\.arpa|localdomain|ts\.net|corp|intranet)$/.test(h) || (!h.includes('.') && /^[a-z0-9-]+$/.test(h));
}

function unicodeHost(h) { try { return nodeUrl.domainToUnicode(h) || h; } catch (_) { return h; } }
// Letters that look the same: Cyrillic and Greek twins, and digits used for letters.
const CONFUSABLE = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'ո': 'n', 'ο': 'o', 'ν': 'v', 'ι': 'i', 'α': 'a', 'ε': 'e', 'ρ': 'p', 'τ': 't', 'κ': 'k', 'ı': 'i', 'ƅ': 'b', 'ɩ': 'i', 'ꓲ': 'l' };
const skeleton = (s) => String(s).normalize('NFKD').replace(/[̀-ͯ]/g, '').replace(/./gu, (c) => CONFUSABLE[c] || c);
const leet = (s, one) => s.replace(/0/g, 'o').replace(/1/g, one).replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't').replace(/@/g, 'a').replace(/\$/g, 's').replace(/rn/g, 'm');

// Does this address pretend to be a provider? Returns { why, brand } or null.
//   embed     the official name inside a longer address (api.openai.com.evil.example)  -> danger
//   homoglyph the same letters from another alphabet, or digits for letters (0penai)   -> danger
//   typo      one or two letters off                                                   -> attention
//   brand     the name of a provider inside another name (openai-proxy.example.com)    -> attention
//   idn       letters from another alphabet, nothing known                             -> attention
function lookalike(host, reg) {
  const h = host;
  for (const d of Object.keys(OFFICIAL)) {
    const i = h.indexOf(d);
    if (i < 0 || (i > 0 && h[i - 1] !== '.')) continue;
    const next = h[i + d.length];
    if (next === '.' || next === '-') return { why: 'embed', brand: OFFICIAL[d] };
  }
  const uni = unicodeHost(h);
  const regUni = unicodeHost(reg);
  const foreign = /[^\x00-\x7f]/.test(uni);
  const labelOf = (s) => s.split('.')[0];
  const regLabel = labelOf(regUni);
  const subLabels = uni.split('.').slice(0, -reg.split('.').length);
  const candidates = [regLabel, ...subLabels];
  for (const raw of candidates) {
    const sk = skeleton(raw);
    const variants = new Set([sk, leet(sk, 'l'), leet(sk, 'i')]);
    for (const v of variants) {
      if (v === raw && !foreign) continue;
      for (const b of BRANDS) if (v === b && raw !== b) return { why: 'homoglyph', brand: BRAND_NAME[b] };
    }
  }
  const sk = skeleton(regLabel);
  for (const b of BRANDS) {
    if (b.length < 6 || sk === b || regLabel === b) continue;
    const d = editDistance(sk, b);
    if (d > 0 && d <= (b.length >= 9 ? 2 : 1)) return { why: 'typo', brand: BRAND_NAME[b] };
  }
  const tokens = (s) => s.split(/[-_0-9]+/).filter((x) => x.length >= 4);
  for (const raw of candidates) {
    for (const tk of tokens(skeleton(raw))) {
      if (BRANDS.includes(tk) && skeleton(raw) !== tk) return { why: 'brand', brand: BRAND_NAME[tk] };
      if (BRANDS.includes(tk) && raw === regLabel) return { why: 'brand', brand: BRAND_NAME[tk] };
    }
  }
  if (foreign || /(^|\.)xn--/.test(h)) return { why: 'idn', brand: '' };
  return null;
}

// What kind of address is this host? { cls, provider?, why?, brand? }
//   official | local | lan | ip | cloud | unknown | tunnel | catchall | lookalike
function classifyHost(host) {
  const h = mapped(String(host || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, ''));
  if (!h) return { cls: 'unknown' };
  if (isLocalHost(h)) return { cls: 'local' };
  if (isLan(h)) return { cls: 'lan' };
  if (isIPv4(h) || h.includes(':')) return { cls: 'ip' };
  if (CATCHALL.test(h)) return { cls: 'catchall' };
  if (TUNNEL.test(h)) return { cls: 'tunnel' };
  const reg = registrable(h);
  if (OFFICIAL[reg]) return { cls: 'official', provider: OFFICIAL[reg] };
  for (const c of CLOUD_API) if (c.re.test(h)) return { cls: 'official', provider: c.name };
  const look = lookalike(h, reg);
  if (look) return { cls: 'lookalike', ...look };
  if (HOSTING.test(h)) return { cls: 'cloud' };
  return { cls: 'unknown' };
}

// An address as written in a settings file. Plain "host:port" (Ollama) is accepted when `bare` is set.
function parseEndpoint(raw, bare = false) {
  let s = String(raw == null ? '' : raw).trim().replace(/^["']|["']$/g, '');
  if (!s || s.length > 2048 || /\s/.test(s)) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    if (!bare || !/^[\w.[\]:-]+(:\d{1,5})?(\/\S*)?$/.test(s) || /^\d+$/.test(s)) return null;
    s = 'http://' + s;
  }
  let u;
  try { u = new URL(s); } catch (_) { return null; }
  if (!/^(https?|wss?):$/.test(u.protocol)) return null;
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  if (!host) return null;
  const secretQuery = [...u.searchParams.keys()].some((k) => /^(key|api[_-]?key|token|access[_-]?token|auth|password|secret|sig|signature)$/i.test(k));
  const clean = `${u.protocol}//${host.includes(':') ? `[${host}]` : host}${u.port ? ':' + u.port : ''}${u.pathname === '/' ? '' : u.pathname}`.slice(0, 200);
  const secure = u.protocol === 'https:' || u.protocol === 'wss:';
  return { host, port: u.port ? Number(u.port) : secure ? 443 : 80, scheme: u.protocol.replace(':', ''), secure, clean, hasLogin: !!(u.username || u.password), hasSecretQuery: secretQuery };
}

const R = (key, params, sev) => ({ key, params: params || {}, sev });
const RANK = { calm: 0, watch: 1, alarm: 2 };
const worst = (reasons) => reasons.reduce((a, r) => (RANK[r.sev] > RANK[a] ? r.sev : a), 'calm');

// The reasons that follow from the address alone. `approvable` says whether you may still approve it:
// a site that only collects what is sent to it, or an address that hides inside a provider's name, never gets a pass.
function judgeHost(p, opts = {}) {
  const c = classifyHost(p.host);
  const reasons = [];
  let approvable = true;
  switch (c.cls) {
    case 'official': reasons.push(R('link.official', { provider: c.provider }, 'calm')); break;
    case 'local': reasons.push(R('link.local', {}, 'calm')); break;
    case 'lan': reasons.push(R('link.lan', { host: p.host }, 'watch')); break;
    case 'cloud': reasons.push(R('link.cloud', { host: p.host }, 'watch')); break;
    case 'unknown': reasons.push(R('link.unknown', { host: p.host }, 'watch')); break;
    case 'ip': reasons.push(R('link.ip', { host: p.host }, 'watch')); break;
    case 'tunnel': reasons.push(R('link.tunnel', { host: p.host }, 'alarm')); break;
    case 'catchall': reasons.push(R('link.catchall', { host: p.host }, 'alarm')); approvable = false; break;
    case 'lookalike': {
      const danger = c.why === 'embed' || c.why === 'homoglyph';
      reasons.push(R(`link.look.${c.why}`, { host: p.host, brand: c.brand || '' }, danger ? 'alarm' : 'watch'));
      if (danger) approvable = false;
      break;
    }
    default: break;
  }
  if (!p.secure && !['local', 'lan'].includes(c.cls)) reasons.push(R('link.clear', { host: p.host }, 'watch'));
  if (p.hasLogin || p.hasSecretQuery) reasons.push(R('link.keyInUrl', {}, 'watch'));
  if (opts.bind && ['0.0.0.0', '::'].includes(p.host)) reasons.push(R('link.bind', { host: p.host }, 'watch'));
  else if (opts.bind && c.cls === 'lan') reasons.push(R('link.bind', { host: p.host }, 'watch'));
  return { cls: c.cls, provider: c.provider, why: c.why, brand: c.brand, reasons, approvable };
}

// Reasons for the address of an MCP server (the MCP check already asks you to approve the server itself):
// only the clearly wrong kinds are added.
function hostReasons(host) {
  const c = classifyHost(host);
  if (c.cls === 'tunnel') return [R('link.tunnel', { host }, 'alarm')];
  if (c.cls === 'catchall') return [R('link.catchall', { host }, 'alarm')];
  if (c.cls === 'ip') return [R('link.ip', { host }, 'watch')];
  if (c.cls === 'lookalike') return [R(`link.look.${c.why}`, { host, brand: c.brand || '' }, c.why === 'embed' || c.why === 'homoglyph' ? 'alarm' : 'watch')];
  return [];
}

// For a program that connects right now: is the name it connects to one of the bad kinds?
function liveHost(host) {
  const c = classifyHost(host);
  if (c.cls === 'tunnel') return { key: 'link.liveTunnel', sev: 'alarm', params: { host } };
  if (c.cls === 'catchall') return { key: 'link.liveCatchall', sev: 'alarm', params: { host } };
  if (c.cls === 'lookalike' && (c.why === 'embed' || c.why === 'homoglyph' || c.why === 'typo')) {
    return { key: 'link.liveLookalike', sev: c.why === 'typo' ? 'watch' : 'alarm', params: { host, brand: c.brand || '?' } };
  }
  return null;
}

// ---------- finding addresses in settings files ----------
const ENDPOINT_VARS = new Set([...C.BASE_URL_VARS, 'ANTHROPIC_BEDROCK_BASE_URL', 'ANTHROPIC_VERTEX_BASE_URL', 'ANTHROPIC_FOUNDRY_BASE_URL', 'GOOGLE_VERTEX_BASE_URL',
  'OPENAI_API_HOST', 'OLLAMA_HOST', 'OLLAMA_BASE_URL', 'HF_ENDPOINT', 'LLM_BASE_URL']);
const BARE_VARS = new Set(['OLLAMA_HOST', 'OLLAMA_BASE_URL']);
const BIND_VARS = new Set(['OLLAMA_HOST']);
const KEY_RE = [
  /(^|[._-])(base[_-]?url|api[_-]?base|api[_-]?host)$/i,
  /override\w*(url|uri)$/i,
  /(^|[._-])(openai|anthropic|claude|gemini|ollama|llm|gpt|azure[_-]?openai)[\w.-]*(endpoint|url|host|uri)$/i,
  /(^|[._-])(model|inference|chat|ai)[\w.-]*(endpoint|api[_-]?url|base[_-]?url)$/i,
];
const wanted = (name) => ENDPOINT_VARS.has(name.toUpperCase()) || KEY_RE.some((re) => re.test(name));
const PAIR = /(?:^|[\s,{;(])["']?([A-Za-z_][\w.-]{2,80})["']?\s*[:=]\s*["']?((?:https?|wss?):\/\/[^\s"'<>,}\]]{3,300}|[A-Za-z0-9_.-]+(?::\d{2,5})?)["']?/g;

// [{ key, name, url, bind, bare }] for every address next to a name that holds an AI address. Works on JSON (with comments),
// TOML, YAML and .env text. `key` is the full path ("env.ANTHROPIC_BASE_URL", "model_providers.local.base_url"); `name` the last part.
function extractEndpoints(text) {
  const body = String(text || '').slice(0, 512 * 1024);
  const out = [];
  const seen = new Set();
  const add = (key, name, val) => {
    if (!wanted(name)) return;
    const bare = BARE_VARS.has(name.toUpperCase());
    if (!bare && !/^(https?|wss?):\/\//i.test(val)) return;
    const id = `${key}|${val}`;
    if (seen.has(id)) return;
    seen.add(id);
    out.push({ key, name, url: val, bare, bind: BIND_VARS.has(name.toUpperCase()) });
  };
  let json = null;
  if (/^\s*[{[]/.test(body)) { try { json = JSON.parse(U.stripJsonComments(body)); } catch (_) { json = null; } }
  if (json && typeof json === 'object') {
    const st = { n: 0 };
    const walk = (node, p) => {
      if (!node || typeof node !== 'object' || st.n++ > 20000) return;
      const arr = Array.isArray(node);
      for (const [k, v] of Object.entries(node)) {
        const np = arr ? `${p}[${k}]` : p ? `${p}.${k}` : k;
        if (typeof v === 'string') { if (!arr) add(np, k, v.trim()); } else walk(v, np);
      }
    };
    walk(json, '');
  } else {
    let section = '';
    for (const line of body.split(/\r?\n/)) {
      if (line.length > 2000 || /^\s*(#|\/\/)/.test(line)) continue;
      const sec =/^\s*\[\[?\s*([^\]\n]{1,80}?)\s*\]\]?\s*$/.exec(line);
      if (sec) { section = sec[1]; continue; }
      for (const m of line.matchAll(PAIR)) add(section ? `${section}.${m[1]}` : m[1], m[1], m[2]);
    }
  }
  return out.slice(0, 40);
}

// Where the programs keep such addresses. The paths use the same spelling as the rest of AgathOS.
const GLOBAL_FILES = [
  ['%USERPROFILE%\\.claude\\settings.json', 'Claude Code'], ['%USERPROFILE%\\.claude\\settings.local.json', 'Claude Code'],
  ['%USERPROFILE%\\.codex\\config.toml', 'Codex CLI'], ['%USERPROFILE%\\.gemini\\settings.json', 'Gemini CLI'], ['%USERPROFILE%\\.qwen\\settings.json', 'Qwen Code'],
  ['%USERPROFILE%\\.continue\\config.json', 'Continue'], ['%USERPROFILE%\\.continue\\config.yaml', 'Continue'], ['%USERPROFILE%\\.config\\opencode\\opencode.json', 'opencode'],
  ['%USERPROFILE%\\.config\\crush\\crush.json', 'Crush'], ['%LOCALAPPDATA%\\crush\\crush.json', 'Crush'], ['%GROK_HOME%\\config.toml', 'Grok Build'],
  ['%USERPROFILE%\\.aider.conf.yml', 'Aider'], ['%APPDATA%\\Code\\User\\settings.json', 'VS Code'], ['%APPDATA%\\Cursor\\User\\settings.json', 'Cursor'],
  ['%APPDATA%\\Windsurf\\User\\settings.json', 'Windsurf'], ['%APPDATA%\\Zed\\settings.json', 'Zed'],
];
const globalFiles = () => GLOBAL_FILES.map(([p, app]) => ({ path: U.expand(p), app }));
// Project files that can hold an address (found while the project folders are walked).
const PROJECT_FILE = /[\\/](?:\.env(?:\.(?!example$|sample$|template$)[\w.-]+)?|\.aider\.conf\.ya?ml|opencode\.json|crush\.json)$|[\\/]\.(?:claude|cursor|vscode|gemini|codex|grok|continue)[\\/][^\\/]+\.(?:json|toml|ya?ml)$/i;
// Folders whose files a program loads by itself when you open a project: a stranger's repository can bring its own.
const AGENT_DIR = /[\\/]\.(?:claude|cursor|vscode|gemini|codex|grok|continue)[\\/]/i;

// ---------- the list of links ----------
const idOf = (...parts) => U.sha256(['link', ...parts].join('|')).slice(0, 16);
const AGENT_NAME = (id) => { const a = C.AGENTS.find((x) => x.id === id); return a ? a.name : id; };

// An agent that is started as an MCP server for another program.
const AGENT_MCP = /\b(claude\s+mcp\s+serve|claude-code[^\n]{0,40}mcp\s+serve|codex\s+(?:mcp-server|mcp\b)|goose\s+mcp|opencode\s+(?:mcp|acp)\b|gemini\b[^\n]{0,60}--(?:experimental-)?acp)\b/i;
function agentMcpReason(cmdline) {
  const m = AGENT_MCP.exec(String(cmdline || ''));
  return m ? R('link.agentMcp', { agent: m[1].replace(/\s+/g, ' ').slice(0, 40) }, 'watch') : null;
}

const NEEDS = new Set(['link.lan', 'link.cloud', 'link.unknown', 'link.ip', 'link.tunnel', 'link.look.typo', 'link.look.brand', 'link.look.idn', 'link.fromProject', 'link.clear', 'link.bind']);

// One address from one settings file or variable. scope: global (your own file) | agentdir (a project file a program loads by itself)
// | project (other project file) | env (a variable). `n` tells apart a name that occurs twice in one file.
function endpointLink(store, { app, file, key, url, via = 'config', bare = false, bind = false, scope = 'global', n = 0 }) {
  const p = parseEndpoint(url, bare);
  if (!p) return null;
  const j = judgeHost(p, { bind });
  const reasons = [...j.reasons];
  // A project that arrives with its own idea of where your AI key goes is the classic way to steal one.
  if (scope === 'agentdir' && ['unknown', 'cloud', 'ip'].includes(j.cls)) reasons.push(R('link.fromProject', {}, 'alarm'));
  const id = idOf(...(n ? [app, file, key, n] : [app, file, key]));
  const hash = U.sha256(`${app}|${key}|${p.clean}`).slice(0, 16);
  const approved = store && store.state.approvals[id];
  let state = worst(reasons);
  let trusted = false;
  if (approved) {
    if (approved.hash !== hash) { reasons.unshift(R('link.changed', { host: p.host }, 'alarm')); state = 'alarm'; }
    else if (j.approvable && reasons.some((r) => NEEDS.has(r.key))) {
      trusted = true;
      for (let i = reasons.length - 1; i >= 0; i--) if (NEEDS.has(reasons[i].key)) reasons.splice(i, 1);
      reasons.unshift(R('link.trusted', {}, 'calm'));
      state = worst(reasons);
    }
  }
  return { id, kind: 'endpoint', app, label: p.clean.replace(/^[a-z]+:\/\//, ''), key, url: p.clean, host: p.host, via, file, scope, cls: j.cls, provider: j.provider || '',
    state, reasons, hash, approved: trusted, approvable: j.approvable, dupOf: null, watcher: 'keys' };
}

// store: for the approvals. mcp / ports: what the scan found. installed: the programs found on this PC.
// files: [{ path, app }] project files that may hold an address. env: [{ v, url, app }]. chains: agents that started agents.
function scan({ store, mcp = [], ports = [], installed = [], files = [], env = [], chains = [] }) {
  const out = [];
  const seen = new Set();
  const push = (l) => { if (l && !seen.has(l.id)) { seen.add(l.id); out.push(l); } };
  const overridden = new Set();
  const done = new Set();
  const occ = new Map();

  const fromFile = (f, scope) => {
    const low = String(f.path).toLowerCase();
    if (done.has(low)) return;
    done.add(low);
    const text = U.readText(f.path, 512 * 1024);
    if (!text) return;
    for (const e of extractEndpoints(text)) {
      const k = `${low}|${e.key}`;
      const n = occ.get(k) || 0;
      occ.set(k, n + 1);
      const l = endpointLink(store, { app: f.app, file: f.path, key: e.key, url: e.url, bare: e.bare, bind: e.bind, scope, n });
      if (l) { push(l); overridden.add(f.app); }
    }
  };
  for (const f of globalFiles()) fromFile(f, 'global');
  for (const f of files.slice(0, 400)) fromFile(f, AGENT_DIR.test(f.path) ? 'agentdir' : 'project');
  for (const e of env) {
    const l = endpointLink(store, { app: e.app, file: 'Environment', key: e.v, url: e.url, via: 'env', bare: BARE_VARS.has(e.v), bind: BIND_VARS.has(e.v), scope: 'env' });
    if (l) push(l);
  }

  // What the other checks found, in the map as well (they are counted there, not here).
  for (const m of mcp) {
    const p = m.url ? parseEndpoint(m.url) : null;
    push({ id: idOf('mcp', m.id), kind: 'mcp', app: m.app, label: m.name, key: m.name, url: p ? p.clean : '', host: p ? p.host : '', via: 'mcp', file: m.file, scope: 'global',
      cls: m.transport === 'http' ? classifyHost(p ? p.host : '').cls : 'stdio', state: m.state, reasons: m.reasons || [], hash: m.hash, approved: !!m.approved, approvable: false, dupOf: 'mcp', mcpId: m.id });
  }
  for (const p of ports) {
    push({ id: idOf('port', p.port), kind: 'server', app: p.product, label: `${p.addr}:${p.port}`, key: String(p.port), url: '', host: p.addr, via: 'port', file: '', scope: 'global',
      cls: p.exposed ? 'exposed' : 'local', state: p.state, reasons: p.reasons || [], hash: `${p.addr}:${p.port}:${p.exposed ? 'open' : 'local'}`, approved: false, approvable: false, dupOf: 'port' });
  }
  for (const a of installed) {
    const provider = AGENT_PROVIDER[a.id];
    if (!provider || overridden.has(a.name)) continue;
    push({ id: idOf('builtin', a.id), kind: 'default', app: a.name, label: provider, key: a.id, url: '', host: '', via: 'builtin', file: '', scope: 'global', cls: 'official', provider,
      state: 'calm', reasons: [R('link.default', { provider }, 'calm')], hash: provider, approved: false, approvable: false, dupOf: 'default' });
  }

  // One program that starts another program that talks to an AI.
  for (const c of chains) {
    const id = idOf('agent', c.from, c.to);
    const approved = store && store.state.approvals[id];
    const trusted = !!approved;
    push({ id, kind: 'agent', app: AGENT_NAME(c.from), label: AGENT_NAME(c.to), key: `${c.from}>${c.to}`, url: '', host: '', via: 'process', file: '', scope: 'global', cls: 'agent',
      state: trusted ? 'calm' : 'watch', reasons: trusted ? [R('link.trusted', {}, 'calm')] : [R('link.agentChain', { from: AGENT_NAME(c.from), to: AGENT_NAME(c.to) }, 'watch')],
      hash: `${c.from}>${c.to}`, approved: trusted, approvable: true, dupOf: null, watcher: 'gate', seen: { first: c.first, last: c.last, n: c.n } });
  }

  const KIND = { endpoint: 0, agent: 1, mcp: 2, server: 3, default: 4 };
  return out.sort((a, b) => (RANK[b.state] - RANK[a.state]) || (KIND[a.kind] - KIND[b.kind]) || a.app.localeCompare(b.app) || a.label.localeCompare(b.label)).slice(0, 300);
}

module.exports = { scan, classifyHost, judgeHost, hostReasons, liveHost, parseEndpoint, extractEndpoints, endpointLink, agentMcpReason, lookalike, registrable, editDistance,
  globalFiles, PROJECT_FILE, AGENT_DIR, ENDPOINT_VARS, BARE_VARS, OFFICIAL, AGENT_PROVIDER, LOCAL_SERVERS, idOf };
