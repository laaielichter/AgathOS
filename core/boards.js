'use strict';
// AgathOS - message boards: the places where programs and agents swap messages and orders.
//
// Whoever can write on a board that an agent reads can steer that agent. Whoever reads a board that an
// agent writes to receives what the agent sends. Attacks on AI agents use both: a chat channel that takes
// orders, a public page that is fetched "every few hours", a network where agents talk to each other,
// a webhook that collects what an agent sends. Many of them are written in a file the person never
// opened: a skill, an instruction file, the workspace of an agent.
//
// AgathOS reads those files and settings as text (nothing is run, nothing is sent) and lists every board:
//   * a chat channel, a public message channel, a public text page, a social board, a network of agents
//   * an outgoing address (a webhook) with a key inside the address
//   * a file that tells the agent to fetch instructions from somewhere and to follow them
//   * an address with invisible characters in it, or a hidden (Tor, I2P) address
//   * a program that connects to a board right now while no file names that board
// A board is calm once you approved it. Keys that are part of an address are never shown, never written
// to the log and never kept: only a one-way fingerprint is, so a swapped key is noticed.
const path = require('path');
const fs = require('fs');
const U = require('./util');
const C = require('./catalog');
const links = require('./links');
const T = require('./textscan');

const R = (key, params, sev) => ({ key, params: params || {}, sev });
const RANK = { calm: 0, watch: 1, alarm: 2 };
const worst = (reasons) => reasons.reduce((a, r) => (RANK[r.sev] > RANK[a] ? r.sev : a), 'calm');
const idOf = (...parts) => U.sha256(['board', ...parts].join('|')).slice(0, 16);
const fpOf = (parts) => (parts.length ? U.sha256(parts.join('\u0001')).slice(0, 12) : '');

// ---------- who is who ----------
// type: chat | webhook | pubsub | paste | social | agentnet.   dir: in (the agent reads) | out (the agent writes) | both.
// open: anybody who knows the name can write.   live: a program that connects here while no file names it is worth a word.
const B = (id, name, type, host, o = {}) => ({ id, name, type, host, dir: 'both', open: false, live: false, ...o });
const CATALOGUE = [
  // chat platforms
  B('discord', 'Discord', 'chat', /(^|\.)(discord(app)?\.com|discord\.gg|discord\.media)$/, { live: true, path: /^\/(api|channels|invite|oauth2|app|gateway)(\/|$)|^\/[\w-]{2,12}$/ }),
  B('telegram', 'Telegram', 'chat', /^(api\.telegram\.org|telegram\.me|t\.me)$/, { live: true }),
  B('slack', 'Slack', 'chat', /(^|\.)(slack\.com|slack-edge\.com)$/, { live: true }),
  B('whatsapp', 'WhatsApp', 'chat', /^(api\.whatsapp\.com|web\.whatsapp\.com|wa\.me)$/, { live: true }),
  B('matrix', 'Matrix', 'chat', /(^|\.)(matrix\.org|matrix\.to|element\.io)$/, { live: true }),
  B('irc', 'IRC', 'chat', /^irc\.[a-z0-9.-]+\.[a-z]{2,}$/, { live: true }),
  B('line', 'LINE', 'chat', /^api\.line\.me$/, { live: true }),
  // outgoing addresses
  B('teams', 'Microsoft Teams', 'webhook', /(^|\.)(webhook\.office\.com|logic\.azure\.com)$/, { dir: 'out' }),
  B('teams', 'Microsoft Teams', 'webhook', /^outlook\.office(365)?\.com$/, { dir: 'out', path: /^\/webhook/ }),
  B('googlechat', 'Google Chat', 'webhook', /^chat\.googleapis\.com$/, { dir: 'out' }),
  B('wecom', 'WeCom', 'webhook', /^qyapi\.weixin\.qq\.com$/, { dir: 'out', path: /\/webhook\// }),
  B('feishu', 'Feishu / Lark', 'webhook', /^open\.(feishu\.cn|larksuite\.com)$/, { dir: 'out', path: /\/bot\// }),
  B('dingtalk', 'DingTalk', 'webhook', /^oapi\.dingtalk\.com$/, { dir: 'out', path: /^\/robot\// }),
  B('ifttt', 'IFTTT', 'webhook', /^maker\.ifttt\.com$/, { dir: 'out' }),
  B('zapier', 'Zapier', 'webhook', /^hooks\.zapier\.com$/, { dir: 'out' }),
  B('make', 'Make', 'webhook', /^hook\.[a-z0-9-]+\.(make|integromat)\.com$/, { dir: 'out' }),
  B('n8n', 'n8n', 'webhook', /(^|\.)app\.n8n\.cloud$/, { dir: 'out' }),
  B('formrelay', 'Form relay', 'webhook', /^(formspree\.io|formsubmit\.co|getform\.io|usebasin\.com|api\.web3forms\.com)$/, { dir: 'out' }),
  B('pushover', 'Pushover', 'webhook', /^api\.pushover\.net$/, { dir: 'out' }),
  B('pushbullet', 'Pushbullet', 'webhook', /^api\.pushbullet\.com$/, { dir: 'out' }),
  // message channels
  B('ntfy', 'ntfy', 'pubsub', /^(ntfy\.sh|ntfy\.[a-z0-9.-]+)$/, { open: /^ntfy\.sh$/, live: true }),
  B('mqtt-public', 'Public MQTT broker', 'pubsub', /^(test\.mosquitto\.org|broker\.hivemq\.com|broker\.emqx\.io|mqtt\.eclipseprojects\.io|broker\.mqttdashboard\.com|public\.mqtthq\.com|mqtt\.eclipse\.org|public\.cloud\.shiftr\.io)$/, { open: true, live: true }),
  B('nats-public', 'Public NATS server', 'pubsub', /^demo\.nats\.io$/, { open: true, live: true }),
  B('pubnub', 'PubNub', 'pubsub', /(^|\.)(pubnub\.com|pndsn\.com)$/, { live: true }),
  B('ably', 'Ably', 'pubsub', /(^|\.)(ably\.io|ably\.net|ably-realtime\.com)$/, { live: true }),
  B('pusher', 'Pusher', 'pubsub', /(^|\.)(pusher\.com|pusherapp\.com|pusherchannels\.com)$/, { live: true }),
  B('piesocket', 'PieSocket', 'pubsub', /(^|\.)(piesocket\.com|socketsbay\.com)$/, { open: true, live: true }),
  B('firebase', 'Firebase Realtime Database', 'pubsub', /(^|\.)firebaseio\.com$/),
  // public text pages (a "dead drop": the owner can change the page at any time)
  B('pastebin', 'Pastebin', 'paste', /^(www\.)?pastebin\.com$/, { dir: 'in', live: true }),
  B('paste', 'Paste site', 'paste', /(^|\.)(paste\.ee|hastebin\.com|rentry\.(co|org)|controlc\.com|dpaste\.(org|com)|justpaste\.it|privatebin\.net|0bin\.net|ix\.io|sprunge\.us|termbin\.com|paste\.rs|bpa\.st|pastes\.io|jpst\.it|pastie\.io|paste\.mozilla\.org|paste\.debian\.net|paste\.ubuntu\.com|pastelink\.net|paste\.sh|cl1p\.net|dontpad\.com|notepad\.cc|anotepad\.com|hackmd\.io|telegra\.ph|write\.as|ghostbin\.[a-z]+|ctxt\.io)$/, { dir: 'in', live: true }),
  B('gist', 'GitHub Gist', 'paste', /^(gist\.github\.com|gist\.githubusercontent\.com)$/, { dir: 'in' }),
  B('gdoc', 'Published Google document', 'paste', /^docs\.google\.com$/, { dir: 'in', path: /^\/(document|spreadsheets|presentation)\/d\/(e\/|[^/]+\/(pub|export|gviz))/ }),
  B('notion', 'Public Notion page', 'paste', /(^|\.)notion\.site$/, { dir: 'in' }),
  B('jsonstore', 'Public JSON store', 'paste', /(^|\.)(jsonbin\.io|jsonblob\.com|npoint\.io|myjson\.(com|online)|kvdb\.io|keyvalue\.xyz|jsonstorage\.net|textdb\.dev)$/, { open: true, live: true }),
  // public boards where anybody can post
  B('reddit', 'Reddit', 'social', /(^|\.)(reddit\.com|redd\.it)$/, { open: true, live: true }),
  B('x', 'X (Twitter)', 'social', /(^|\.)(x\.com|twitter\.com|t\.co)$/, { open: true, live: true }),
  B('bluesky', 'Bluesky', 'social', /(^|\.)(bsky\.social|bsky\.app|bsky\.network)$/, { open: true, live: true }),
  B('mastodon', 'Mastodon', 'social', /^(mastodon\.(social|online|world)|fosstodon\.org|infosec\.exchange|hachyderm\.io|mas\.to)$/, { open: true, live: true }),
  B('hn', 'Hacker News', 'social', /^news\.ycombinator\.com$/, { open: true }),
  B('4chan', '4chan', 'social', /(^|\.)(4chan|4channel)\.org$/, { open: true, live: true }),
  B('lemmy', 'Lemmy', 'social', /^lemmy\.(world|ml)$/, { open: true, live: true }),
  B('nostr', 'Nostr relay', 'social', /^(relay\.damus\.io|nos\.lol|relay\.nostr\.band|relay\.primal\.net|nostr\.wine|relay\.snort\.social|purplepag\.es|offchain\.pub)$/, { open: true, live: true }),
  // networks where AI agents talk to each other
  B('moltbook', 'Moltbook', 'agentnet', /(^|\.)moltbook\.com$/, { live: true }),
  B('agentverse', 'Agentverse', 'agentnet', /(^|\.)agentverse\.ai$/, { live: true }),
  B('agentai', 'agent.ai', 'agentnet', /(^|\.)agent\.ai$/, { live: true }),
];
// Boards that are recognised by the shape of the address, on any host.
const PATH_RULES = [
  { id: 'matrix', name: 'Matrix', type: 'chat', dir: 'both', re: /^\/_matrix\/(client|federation)\// },
  { id: 'a2a', name: 'Agent-to-agent (A2A)', type: 'agentnet', dir: 'both', re: /^\/\.well-known\/agent(-card)?\.json$/ },
  { id: 'hook', name: 'Webhook', type: 'webhook', dir: 'out', re: /^\/hooks\/[A-Za-z0-9]{16,}/ },
  { id: 'n8n', name: 'n8n', type: 'webhook', dir: 'out', re: /^\/webhook(-test)?\/[0-9a-f-]{20,}/i },
];
const SCHEMES = { mqtt: ['mqtt', 'MQTT', 'pubsub'], mqtts: ['mqtt', 'MQTT', 'pubsub'], nats: ['nats', 'NATS', 'pubsub'], amqp: ['amqp', 'AMQP', 'pubsub'], amqps: ['amqp', 'AMQP', 'pubsub'],
  irc: ['irc', 'IRC', 'chat'], ircs: ['irc', 'IRC', 'chat'] };

function finish(e, h) {
  return { id: e.id, name: e.name, type: e.type, dir: e.dir, open: e.open instanceof RegExp ? e.open.test(h) : !!e.open, live: !!e.live, byPath: false };
}

// Which board is this address? null when it is none. `pathname` may be null (a program that only looked up a name).
function matchBoard(host, pathname, protocol) {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!h) return null;
  const p = pathname == null ? null : String(pathname);
  const proto = String(protocol || '').replace(/:$/, '').toLowerCase();
  if (/\.(onion|i2p)$/.test(h)) return { id: 'onion', name: h.endsWith('.i2p') ? 'I2P' : 'Tor', type: 'onion', dir: 'both', open: false, live: true, byPath: false };
  if (/^(api|docs|status|support)\.slack\.com$/.test(h) && p !== null && !/^\/(api|services|triggers)\//.test(p)) return null;
  for (const e of CATALOGUE) if (e.host.test(h) && (!e.path || p === null || e.path.test(p))) return finish(e, h);
  if (SCHEMES[proto]) { const [id, name, type] = SCHEMES[proto]; return { id, name, type, dir: 'both', open: false, live: false, byPath: false }; }
  if (p !== null) for (const e of PATH_RULES) if (e.re.test(p)) return { id: e.id, name: e.name, type: e.type, dir: e.dir, open: false, live: false, byPath: true };
  return null;
}

// A program that connects right now: is it a board that is worth a word? { id, name, type, open } or null.
function liveBoard(host) {
  const b = matchBoard(host, null, 'https');
  return b && b.live ? { id: b.id, name: b.name, type: b.type, open: !!b.open } : null;
}

// ---------- keys inside addresses ----------
// [host, pattern with 3 groups: the part to keep, the key, the rest, hook]: the key is hidden, the first and last part stay.
const KEY_PATHS = [
  { host: /discord/, re: /^(\/api\/(?:v\d+\/)?webhooks\/\d+\/)([\w-]+)(.*)$/, hook: true },
  { host: /slack/, re: /^(\/services\/T\w+\/B\w+\/)(\w+)(.*)$/, hook: true },
  { host: /slack/, re: /^(\/triggers\/\w+\/\w+\/)(\w+)(.*)$/, hook: true },
  { host: /telegram/, re: /^(\/(?:file\/)?bot\d{4,}:)([\w-]+)(.*)$/, hook: false },
  { host: /ifttt/, re: /^(\/trigger\/[\w.-]+\/(?:json\/)?with\/key\/)([\w-]+)(.*)$/, hook: true },
  { host: /ifttt/, re: /^(\/use\/)([\w-]+)(.*)$/, hook: true },
  { host: /zapier/, re: /^(\/hooks\/catch\/\d+\/)(\w+)(.*)$/, hook: true },
  { host: /make\.com|integromat/, re: /^(\/)([\w-]{16,})()$/, hook: true },
  { host: /office\.com/, re: /^(\/webhook(?:b2)?\/)(.+)()$/, hook: true },
  { host: /logic\.azure/, re: /^(\/workflows\/)(\w+)(.*)$/, hook: true },
  { host: /googleapis/, re: /^(\/v1\/spaces\/)([\w-]+)(.*)$/, hook: true },
  { host: /feishu|larksuite/, re: /^(\/open-apis\/bot\/v2\/hook\/)([\w-]+)(.*)$/, hook: true },
  { host: /pubnub|pndsn/, re: /^(\/(?:publish|subscribe)\/)([\w-]+)(.*)$/, hook: false },
  { host: null, re: /^(\/hooks\/)([\w/-]{16,})()$/, hook: true },
  { host: null, re: /^(\/webhook(?:-test)?\/)([0-9a-f-]{20,})(.*)$/i, hook: true },
];
const SECRET_QUERY = /^(key|api[_-]?key|apikey|token|access[_-]?token|auth|password|pwd|secret|sig|signature|code|jwt|bearer|k)$/i;
const looksLikeToken = (s) => s.length >= 24 && /^[A-Za-z0-9_-]+$/.test(s) && ((/[A-Za-z]/.test(s) && /\d/.test(s)) || s.length >= 40);

// What may be shown of an address: { label, keys, ids, hook }. The label has no key, no login, no query.
function maskUrl(u) {
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  const keys = [];
  const ids = [];
  let hook = false;
  let p = u.pathname === '/' ? '' : decodeURIComponentSafe(u.pathname);
  if (p) {
    for (const k of KEY_PATHS) {
      if (k.host && !k.host.test(host)) continue;
      const m = k.re.exec(p);
      if (!m) continue;
      keys.push(m[2]);
      hook = k.hook;
      p = m[1] + '•••' + (m[3] || '');
      break;
    }
    p = p.split('/').map((seg) => {
      if (!looksLikeToken(seg)) return seg;
      ids.push(seg);
      return `${seg.slice(0, 4)}…${seg.slice(-2)}`;
    }).join('/');
  }
  for (const [k, v] of u.searchParams) if (SECRET_QUERY.test(k) && v) keys.push(`${k}=${v}`);
  if (u.password) keys.push(u.password);
  const scheme = /^(https?|wss?)$/.test(u.protocol.replace(':', '')) ? '' : u.protocol + '//';
  const port = u.port && !((u.protocol === 'mqtt:' && u.port === '1883') || (u.protocol === 'mqtts:' && u.port === '8883')) ? ':' + u.port : '';
  // No control characters and no invisible ones: what is shown is what is there.
  const label = T.stripHidden(`${scheme}${host.includes(':') ? `[${host}]` : host}${port}${p}${u.search ? '?…' : ''}`).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 160);
  return { label, host, keys, ids, hook };
}
function decodeURIComponentSafe(s) { try { return decodeURIComponent(s); } catch (_) { return s; } }

// ---------- what the words around an address say ----------
const NW = '(?![\\p{L}\\p{N}])';
const words = (list) => list.map((s) => (s.endsWith('$') ? s.slice(0, -1) + NW : s));
function matcher(latin, cjk = []) {
  const a = latin.length ? new RegExp(`(?<![\\p{L}\\p{N}])(?:${words(latin).join('|')})`, 'iu') : null;
  const b = cjk.length ? new RegExp(cjk.join('|'), 'u') : null;
  return (s) => (a !== null && a.test(s)) || (b !== null && b.test(s));
}
// Fetch / read.
const READ = matcher([
  'fetch(?:es|ed|ing)?$', 'poll(?:s|ed|ing)?$', 'read(?:s|ing)?$', 'check(?:s|ed|ing)?$', 'listen(?:s|ed|ing)?$', 'subscrib(?:e|es|ed|ing)$', 'monitor(?:s|ed|ing)?$',
  'watch(?:es|ed|ing)?$', 'receiv(?:e|es|ed|ing)$', 'pull(?:s|ed|ing)?$', 'download(?:s|ed|ing)?$', 'retriev(?:e|es|ed|ing)$', 'curl$', 'wget$', 'visit(?:s|ed|ing)?$',
  'brows(?:e|es|ed|ing)$', 'scan(?:s|ned|ning)?$', 'load(?:s|ed|ing)?$',
  'haal', 'ophal', 'lees$', 'leest$', 'lezen$', 'controleer', 'raadpleeg', 'luister', 'abonneer',
  'hol(?:e|en|t)$', 'abruf', 'ruf(?:e|t)$', 'lies$', 'liest$', 'lesen$', 'prüf', 'überprüf', 'abonnier', 'lade$', 'lädt$', 'überwach',
  'récup', 'lis$', 'lire$', 'consult', 'vérifi', 'écout', 'abonn', 'télécharg', 'surveill',
  'obt[eé]n', 'recupera', 'lee$', 'leer$', 'revisa', 'verifica', 'escucha', 'suscr', 'descarga', 'monitorea',
  'leggi$', 'leggere$', 'controlla', 'ascolta', 'iscriv', 'scarica', 'monitora',
  'busca$', 'obtenha', 'leia$', 'verifique', 'escute', 'inscreva', 'baixe',
  'получ', 'прочит', 'читай', 'проверя', 'проверь', 'скача', 'подпиш', 'следи', 'загруз',
], ['获取', '读取', '查看', '检查', '拉取', '下载', '订阅', '监听', '轮询', '抓取', '取得', '読み', '確認', 'チェック', 'ダウンロード', '購読', '監視', '가져', '읽', '확인', '다운로드', '구독']);
// Send / write.
const POST = matcher([
  'post(?:s|ed|ing)?$', 'send(?:s|ing)?$', 'sent$', 'publish(?:es|ed|ing)?$', 'notif(?:y|ies|ied|ying)$', 'upload(?:s|ed|ing)?$', 'submit(?:s|ted|ting)?$', 'repl(?:y|ies|ied|ying)$',
  'forward(?:s|ed|ing)?$', 'broadcast(?:s|ing)?$', 'announc(?:e|es|ed|ing)$', 'push(?:es|ed|ing)?$', 'webhook', 'report(?:s|ed|ing)? back$', 'writ(?:e|es|ing) to$', 'dm$',
  'stuur', 'verstuur', 'verzend', 'publiceer', 'antwoord', 'reageer', 'plaats',
  'send(?:e|et|en)$', 'schick', 'veröffentlich', 'poste$', 'antworte', 'hochlad',
  'envoi', 'publi', 'répond', 'notifi',
  'env[ií]a', 'publica', 'responde', 'notifica',
  'invia', 'pubblica', 'rispondi', 'carica',
  'envie', 'publique', 'responda', 'notifique',
  'отправ', 'публик', 'ответ', 'сообщи', 'пиш',
], ['发送', '发布', '推送', '通知', '回复', '上传', '发帖', '送信', '投稿', '返信', '보내', '전송', '게시', '답장']);
// Words for a place where messages are left.
const BOARDWORD = matcher([
  'channel', 'board$', 'forum', 'inbox', 'feed$', 'topic', 'room$', 'thread', 'bot$', 'bots$', 'broker', 'queue', 'chat', 'group$', 'subreddit', 'mailbox',
  'kanaal', 'kanal', 'canal', 'salon', 'канал', 'чат', 'форум',
], ['频道', '聊天', '论坛', 'チャンネル', 'チャット', '掲示板', '채널', '채팅', '게시판']);
// Follow / obey.
const OBEY = matcher([
  'follow(?:s|ed|ing)?$', 'obey(?:s|ed|ing)?$', 'execut(?:e|es|ed|ing)$', 'carry(?:ing)? out$', 'do what$', 'act(?:s|ing)? on$', 'compl(?:y|ies|ying) with$',
  'take your (?:instructions|orders|commands) from$', 'as (?:your )?(?:instructions|orders|commands)$', 'treat (?:it|them|this|these) as$', 'run (?:it|them|the (?:commands?|instructions?|tasks?))$',
  'volg$', 'volgt$', 'gehoorzaam', 'voer .{0,20}uit$', 'uitvoeren$',
  'befolge', 'folge$', 'folgen$', 'gehorche', 'führe .{0,20}aus$', 'ausführen$',
  'suis$', 'suivre$', 'suivez', 'obéis', 'exécute', 'applique',
  'sigue$', 'seguir$', 'obedece', 'ejecuta',
  'segui$', 'seguire$', 'obbedisci', 'esegui',
  'siga$', 'obedeça', 'execute$',
  'следуй', 'следовать', 'выполня', 'исполня', 'слушайся',
], ['遵循', '按照', '服从', '执行', '照做', '従っ', '従い', '実行', '따르', '따라', '실행', '복종']);
// What is fetched: instructions, commands, tasks.
const ORDER = matcher([
  'instruction', 'command', 'orders?$', 'tasks?$', 'directive', 'mission', 'assignment', 'prompts?$', 'playbook', 'to-?do', 'heartbeat', 'guidance',
  'instructie', 'opdracht', 'bevel', 'taken$', 'taak$', 'aanwijzing', 'richtlijn',
  'anweisung', 'befehl', 'aufgabe', 'auftr', 'vorgabe', 'instruktion',
  'consigne', 'ordre', 'tâche', 'directive',
  'instrucci', 'órdenes', 'ordenes', 'comandos', 'tareas', 'directrices',
  'istruzion', 'comand', 'ordini', 'compiti',
  'instruç', 'instruc', 'ordens', 'tarefa',
  'инструкц', 'команд', 'приказ', 'задани', 'указани',
], ['指令', '命令', '指示', '任务', '说明', 'タスク', 'コマンド', '지시', '명령', '작업', '지침']);
// New, latest, waiting.
const FRESH = matcher([
  'new(?:est)?$', 'latest$', 'updated?$', 'fresh$', 'pending$', 'current$', 'remote$', 'live$', 'unread$',
  'nieuwe', 'nieuwste', 'laatste', 'actuele', 'openstaande', 'ongelezen',
  'neue', 'aktuell', 'ausstehende', 'ungelesen',
  'nouvelle', 'dernière', 'derniere', 'récente', 'en attente', 'non lu',
  'nuev', 'últim', 'reciente', 'pendiente',
  'nuove', 'ultime', 'recenti', 'non lett',
  'novas?$', 'pendentes',
  'нов', 'последн', 'актуальн', 'непрочитан',
], ['最新', '新的', '未读', '待处理', '新しい', '未読', '최신', '새로운', '읽지 않은']);
// Again and again.
const PERIODIC = new RegExp([
  String.raw`(?:every|each)\s+(?:other\s+|few\s+)?(?:\d+\+?\s*(?:s|secs?|seconds?|m|mins?|minutes?|h|hrs?|hours?|d|days?|w|weeks?)|second|minute|hour|day|morning|evening|night|week|weekday|session|run|task|turn|time|heartbeat|tick|cycle|start)${NW}`,
  String.raw`(?<![\p{L}\p{N}])(?:hourly|daily|nightly|periodic(?:ally)?|regular(?:ly)?|continuous(?:ly)?|repeated(?:ly)?|heartbeat|cron|schedul(?:e|ed|es|ing)|polling|on a loop|in a loop|keep checking|keep polling|at (?:the )?(?:start|beginning) of (?:each|every|any|a) (?:session|run|task|turn|conversation)|before (?:each|every|any) (?:task|action|step|response|answer)|on (?:each|every) (?:startup|start|launch|boot|session|run|turn)|\d+\+?\s*(?:hours?|hrs?|minutes?|mins?|days?)\s+(?:since|ago)|since\s+(?:the\s+)?last)${NW}`,
  String.raw`(?<![\p{L}\p{N}])(?:elke\s+(?:\d+\s*(?:seconden|minuten|uur|uren|dagen)|minuut|dag|week|sessie|keer|beurt)|elk\s+uur|dagelijks|regelmatig|periodiek|voortdurend|continu|stelselmatig)${NW}`,
  String.raw`(?<![\p{L}\p{N}])(?:(?:alle|jede[nrs]?)\s+(?:\d+\s*(?:sekunden|minuten|stunden|tage)|minute|stunde|tag|woche|sitzung)|stündlich|täglich|regelmäßig|ständig|fortlaufend|periodisch)${NW}`,
  String.raw`(?<![\p{L}\p{N}])(?:toutes\s+les\s+(?:\d+\s*(?:secondes|minutes|heures)|heures)|chaque\s+(?:minute|heure|jour|session|fois)|quotidien|régulièrement|en\s+continu|périodiquement|en\s+permanence)${NW}`,
  String.raw`(?<![\p{L}\p{N}])(?:cada\s+(?:\d+\s*(?:segundos|minutos|horas|días|dias)|minuto|hora|día|dia|sesión|sesion|vez)|diariamente|regularmente|periódicamente|periodicamente|continuamente|constantemente)${NW}`,
  String.raw`(?<![\p{L}\p{N}])(?:ogni\s+(?:\d+\s*(?:secondi|minuti|ore|giorni)|minuto|ora|giorno|sessione|volta)|quotidianamente|regolarmente|periodicamente|continuamente)${NW}`,
  String.raw`(?<![\p{L}\p{N}])(?:a\s+cada\s+(?:\d+\s*(?:segundos|minutos|horas|dias)|minuto|hora|dia|sessão|sessao|vez)|diariamente|regularmente|periodicamente|continuamente)${NW}`,
  String.raw`(?<![\p{L}\p{N}])(?:кажд(?:ые|ый|ую|ое)\s+(?:\d+\s*)?(?:секунд|минут|час|день|дня|дней|сессию|раз)|ежедневно|регулярно|постоянно|периодически|непрерывно)`,
  String.raw`每\s*\d*\s*(?:秒|分钟|分鐘|小时|小時|天|次|个小时)|定期|定时|定時|持续|持續|不断|不斷|\d+\s*(?:秒|分|時間|日)ごと|毎(?:時間|分|日|回)|定期的|常に|\d+\s*(?:초|분|시간|일)마다|매(?:시간|분|일|번)|정기적|계속`,
].join('|'), 'iu');

const URL_RE = /(?<![\w])(?:https?|wss?|mqtts?|nats|ircs?|amqps?):\/\/[^\s"'`<>\\^{}|]{3,500}/gi;
const TRAIL = /[)\].,;:!?'"*_`>}]+$/;

// The words around an address, without the addresses themselves (a name such as "readthedocs.io" says nothing).
function signals(ctx) {
  const s = String(ctx || '').replace(URL_RE, ' ');
  return { read: READ(s), post: POST(s), board: BOARDWORD(s), obey: OBEY(s), order: ORDER(s), periodic: PERIODIC.test(s), fresh: FRESH(s) };
}
// "Fetch this again and again and do what it says": a standing order from somewhere else. g1: the line with the address; g2: the lines around it.
const asksOrders = (g1, g2 = g1) => g1.read && ((g1.obey && (g1.order || g2.order || g1.periodic || g2.periodic)) || (g1.order && (g1.periodic || g1.fresh)) || (g1.periodic && g2.order));

// Pages that explain things: reading them is not taking orders (unless it is meant to happen again and again).
const DOCS_HOST = /^(docs?|developers?|learn|help|support|wiki|api-docs|dev|devdocs)\.|(^|\.)(readthedocs\.io|wikipedia\.org|developer\.mozilla\.org|npmjs\.com|pypi\.org|nodejs\.org|python\.org|stackoverflow\.com|docs\.rs|crates\.io|github\.com|gitlab\.com|microsoft\.com|apple\.com|google\.com)$/i;
// Names made up for examples (RFC 2606): a sentence with such an address is a lesson, not an order.
const PLACEHOLDER_HOST = /(^|\.)(example\.(com|org|net)|example|test|invalid|localhost)$/i;
const DOCS_PATH = /^\/(docs?|documentation|guides?|manual|tutorials?|reference|wiki|learn|help|handbook|getting-started)(\/|$|\.)/i;
const exemptDocs = (host, pathname) => {
  const c = links.classifyHost(host);
  return c.cls === 'official' || c.cls === 'local' || DOCS_HOST.test(host) || DOCS_PATH.test(pathname || '');
};

// ---------- finding boards in a text ----------
const DIRS = new Set(['in', 'out', 'both']);
const mergeDir = (a, b) => (a === b ? a : DIRS.has(a) && DIRS.has(b) ? 'both' : a || b);

// Everything in one text file that looks like a board. `kind`: instruction | skill | config | env.
// Returns small objects: no key, no password, no address with a query is kept in them.
function extract(text, { kind = 'instruction' } = {}) {
  const body = String(text || '').slice(0, 512 * 1024);
  if (!body) return [];
  const hits = new Map();
  const put = (h) => {
    const old = hits.get(h.id);
    if (!old) { if (hits.size < 60) hits.set(h.id, h); return; }
    old.dir = mergeDir(old.dir, h.dir);
    for (const f of ['open', 'orders', 'periodic', 'hidden', 'clear']) old[f] = old[f] || h[f];
    if (!old.openChannel && h.openChannel) old.openChannel = h.openChannel;
    if (!old.setting && h.setting) old.setting = h.setting;
    for (const f of h.fps || []) if (f && !old.fps.includes(f)) old.fps.push(f);
  };
  const mk = (o) => ({ dir: 'both', open: false, orders: false, periodic: false, hidden: false, clear: false, openChannel: '', setting: '', fps: [], ...o });
  const likeText = kind === 'instruction' || kind === 'skill';
  try { fromAddresses(body, kind, likeText, put, mk); } catch (_) { /* a text that cannot be read gives nothing */ }
  // Channels that are switched off in the settings do not count, whatever key is left in the file.
  const off = new Set();
  try { fromSettings(body, kind, put, mk, off); } catch (_) { /* same */ }
  try { fromTokens(body, put, mk, off); } catch (_) { /* same */ }
  try { fromNames(body, likeText, put, mk); } catch (_) { /* same */ }
  return [...hits.values()].map((h) => { const { fps, ...rest } = h; return { ...rest, fp: fpOf(fps.filter(Boolean).sort()) }; });
}

function lineIndex(body) {
  const starts = [0];
  for (let i = body.indexOf('\n'); i >= 0 && starts.length < 200000; i = body.indexOf('\n', i + 1)) starts.push(i + 1);
  return starts;
}
function lineOf(starts, idx) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= idx) lo = mid; else hi = mid - 1; }
  return lo;
}
// The words around an address: its own line first; when that says nothing, the lines next to it.
function around(body, starts, idx, len, reach) {
  const li = lineOf(starts, idx);
  const from = starts[Math.max(0, li - reach)];
  const last = Math.min(starts.length - 1, li + reach);
  const to = last + 1 < starts.length ? starts[last + 1] - 1 : body.length;
  return body.slice(Math.max(from, idx - 350), Math.min(to, idx + len + 350));
}

function fromAddresses(body, kind, likeText, put, mk) {
  if (!body.includes('://')) return;
  const literalOnly = kind === 'env' || kind === 'config';        // settings: a name in a setting is on purpose, words around it do not exist
  const starts = lineIndex(body);
  let n = 0;
  for (const m of body.matchAll(URL_RE)) {
    if (n++ >= 600) break;
    const raw = m[0].replace(TRAIL, '');
    const hid = T.hiddenUnicode(raw);
    const hidden = !!(hid && (hid.zeroWidth || hid.bidi || hid.tags));
    let u;
    try { u = new URL(T.stripHidden(raw)); } catch (_) { continue; }
    const proto = u.protocol.replace(':', '');
    const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    if (!host || !/^(https?|wss?|mqtts?|nats|ircs?|amqps?)$/.test(proto)) continue;
    // A pattern such as https://*/* or a made-up example name is no address.
    if (!/^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/.test(host) && !host.includes(':')) continue;
    const masked = maskUrl(u);
    let b = matchBoard(host, u.pathname, u.protocol);
    const cls = links.classifyHost(host).cls;
    // A tunnel or a site that only collects data, named in a file that an agent reads: never normal.
    const collector = !b && !literalOnly && (cls === 'tunnel' || cls === 'catchall');
    if (collector) b = { id: 'collector', name: host, type: 'webhook', dir: 'out', open: false, live: false, byPath: false };
    const g1 = signals(around(body, starts, m.index, raw.length, 0));
    const g2 = signals(around(body, starts, m.index, raw.length, 2));
    const acts = (x) => x.read || x.post || x.periodic;
    const g = acts(g1) ? g1 : g2;
    const placeholder = PLACEHOLDER_HOST.test(host);
    // "Fetch this and do what it says", again and again or just once: the line with the address must say it; the lines around it may add when and what.
    const ordersAsked = kind !== 'code' && !placeholder && (host.includes('.') || host.includes(':')) && asksOrders(g1, g2) && (!exemptDocs(host, u.pathname) || g1.periodic || g2.periodic);
    const strong = !!(b && (masked.hook || b.type === 'onion' || SCHEMES[proto] || collector));
    let keep = false;
    if (b) {
      const inCode = kind === 'code';          // a script uses the chat, the channel and the network it names; a page or a social site in a comment is only a reference
      keep = strong || literalOnly || b.type === 'agentnet' || acts(g1) || (inCode ? ['chat', 'pubsub', 'webhook'].includes(b.type) : (g2.read || g2.post) && g1.board);
    }
    if (ordersAsked) keep = true;
    if (hidden && !literalOnly && !placeholder) keep = true;
    if (!keep) continue;
    const type = b ? (masked.hook && b.type !== 'webhook' ? 'webhook' : b.type) : hidden ? 'hidden' : 'orders';
    let dir = masked.hook ? 'out' : b ? b.dir : 'in';
    if (!masked.hook) {
      if (ordersAsked) dir = g1.post ? 'both' : 'in';
      else if (g.read && !g.post) dir = 'in';
      else if (g.post && !g.read) dir = 'out';
      else if (g.read && g.post) dir = 'both';
    }
    put(mk({
      id: idOf(...identity(b, type, host, masked)), type, bid: b ? b.id : '', name: b && b.id !== 'collector' ? b.name : host, host, label: masked.label, dir,
      open: !!(b && b.open), live: !!(b && b.live), orders: ordersAsked, periodic: ordersAsked && (g1.periodic || g2.periodic), hidden,
      clear: (proto === 'http' || proto === 'ws') && !['local', 'lan'].includes(cls) && !(b && b.type === 'onion'),
      setting: literalOnly ? settingBefore(body, m.index) : '', fps: [fpOf(masked.keys)],
    }));
  }
}

// What makes two addresses "the same board". A chat service, a social board or a network of agents is one board, whatever the path;
// a webhook or a page is only the same when the address is the same.
function identity(b, type, host, masked) {
  if (type === 'orders' || type === 'hidden') return [type, masked.label, fpOf(masked.ids)];
  if (type === 'onion') return ['onion', host];
  if (masked.hook || type === 'webhook' || type === 'paste') return [type, b ? b.id : '', masked.label, fpOf(masked.ids)];
  if (b && b.id === 'ntfy') return ['pubsub', 'ntfy', host, (masked.label.split('/')[1] || '')];
  if (b && ['mqtt', 'nats', 'amqp', 'irc'].includes(b.id)) return [type, b.id, host];
  if (b && b.byPath) return [type, b.id, host];
  return [type, b ? b.id : host];
}

function settingBefore(body, idx) {
  const m = /([A-Za-z_][\w.-]{1,60})["']?\s*[:=]\s*["']?$/.exec(body.slice(Math.max(0, idx - 90), idx));
  return m ? m[1] : '';
}

// Bots and apps of chat platforms are found by the shape of their key.
const TOKEN_SHAPES = [
  { bid: 'telegram', re: /\b\d{8,10}:AA[\w-]{30,40}\b/g },
  { bid: 'discord', re: /\b[MNO][A-Za-z\d_-]{23,27}\.[\w-]{6}\.[\w-]{27,40}\b/g },
  { bid: 'slack', re: /\b(?:xox[abprs]|xapp)-[\w-]{10,}/g },
  { bid: 'matrix', re: /\bsyt_[\w-]{20,}/g },
];
const CHAT = {
  telegram: { name: 'Telegram', host: 'api.telegram.org', type: 'chat' }, discord: { name: 'Discord', host: 'discord.com', type: 'chat' },
  slack: { name: 'Slack', host: 'slack.com', type: 'chat' }, whatsapp: { name: 'WhatsApp', host: 'web.whatsapp.com', type: 'chat' },
  matrix: { name: 'Matrix', host: 'matrix.org', type: 'chat' }, signal: { name: 'Signal', host: 'signal.org', type: 'chat' },
  mattermost: { name: 'Mattermost', host: 'mattermost.com', type: 'chat' }, msteams: { name: 'Microsoft Teams', host: 'teams.microsoft.com', type: 'chat' },
  teams: { name: 'Microsoft Teams', host: 'teams.microsoft.com', type: 'chat' }, irc: { name: 'IRC', host: 'irc', type: 'chat' },
  googlechat: { name: 'Google Chat', host: 'chat.google.com', type: 'chat' }, imessage: { name: 'iMessage', host: 'imessage', type: 'chat' },
  bluebubbles: { name: 'iMessage (BlueBubbles)', host: 'bluebubbles', type: 'chat' }, line: { name: 'LINE', host: 'api.line.me', type: 'chat' },
  zulip: { name: 'Zulip', host: 'zulipchat.com', type: 'chat' }, twitch: { name: 'Twitch', host: 'twitch.tv', type: 'chat' },
  feishu: { name: 'Feishu / Lark', host: 'open.feishu.cn', type: 'chat' }, lark: { name: 'Feishu / Lark', host: 'open.feishu.cn', type: 'chat' },
  dingtalk: { name: 'DingTalk', host: 'oapi.dingtalk.com', type: 'chat' }, wecom: { name: 'WeCom', host: 'qyapi.weixin.qq.com', type: 'chat' },
  nostr: { name: 'Nostr', host: 'nostr', type: 'social' },
};
const chatId = (bid) => (bid === 'teams' ? 'msteams' : bid === 'lark' ? 'feishu' : bid);
const chatHit = (bid, mk, o = {}) => {
  const c = CHAT[bid];
  return mk({ id: idOf(c.type, chatId(bid)), type: c.type, bid: chatId(bid), name: c.name, host: c.host, label: /\./.test(c.host) ? c.host : c.name, dir: 'both', live: true, ...o });
};
function fromTokens(body, put, mk, off) {
  if (!/(?:xox|xapp-|syt_|:AA|\.[\w-]{6}\.)/.test(body)) return;
  for (const t of TOKEN_SHAPES) {
    if (off.has(t.bid)) continue;
    for (const m of body.matchAll(t.re)) {
      put(chatHit(t.bid, mk, { fps: [fpOf([m[0]])], setting: '' }));
      break;
    }
  }
}

// Settings that switch a chat channel on: a `channels.telegram` block, a TELEGRAM_BOT_TOKEN line.
const CHANNEL_PATH = /(?:^|\.)(?:channels|integrations|connectors|bots|messaging|chat)\.([A-Za-z0-9_-]+)$/i;
const POLICY = /^(?:dm|group)[_-]?policy$/i;
const ALLOW = /^(?:allow[_-]?from|allowed[_-]?(?:users|senders|chats|ids)|allowlist)$/i;
const ENV_CHAT = /^[ \t]*(?:export[ \t]+)?((?:TELEGRAM|DISCORD|SLACK|WHATSAPP|MATRIX|MATTERMOST|TWITCH|SIGNAL|ZULIP|MSTEAMS|TEAMS)[A-Z0-9_]*(?:TOKEN|WEBHOOK|SECRET|APIKEY|API_KEY|PASSWORD))[ \t]*=[ \t]*(["']?)([^\s"'#]{6,})\2/gim;
const PLACEHOLDER = /^(your|xxx+|change|placeholder|example|todo|none|null|<|\$|\.\.\.|\*+$)/i;

function parseLoose(body) {
  const s = U.stripJsonComments(body);
  try { return JSON.parse(s); } catch (_) { /* JSON5 style: bare keys, single quotes */ }
  try {
    const t = s.replace(/([{,]\s*)([A-Za-z_$][\w$-]*)\s*:/g, '$1"$2":').replace(/'([^'\\\n]*)'/g, (_, x) => JSON.stringify(x)).replace(/,\s*([}\]])/g, '$1');
    return JSON.parse(t);
  } catch (_) { return null; }
}
const openIn = (node, p) => {
  const found = [];
  for (const [k, v] of Object.entries(node)) {
    if (POLICY.test(k) && String(v).toLowerCase() === 'open') found.push(`${p}.${k}`);
    else if (ALLOW.test(k) && Array.isArray(v) && v.some((x) => String(x).trim() === '*')) found.push(`${p}.${k}`);
  }
  return found[0] || '';
};

function fromSettings(body, kind, put, mk, off) {
  if (kind === 'env') {
    for (const m of body.matchAll(ENV_CHAT)) {
      if (PLACEHOLDER.test(m[3])) continue;
      const bid = m[1].split('_')[0].toLowerCase();
      if (CHAT[bid]) put(chatHit(bid, mk, { setting: m[1], fps: [fpOf([m[3]])] }));
    }
    return;
  }
  if (kind !== 'config') return;
  const trimmed = body.trimStart();
  const json = trimmed[0] === '{' || trimmed[0] === '[' ? parseLoose(body) : null;
  if (json && typeof json === 'object') {
    const st = { n: 0 };
    const walk = (node, p) => {
      if (!node || typeof node !== 'object' || st.n++ > 20000) return;
      const arr = Array.isArray(node);
      for (const [k, v] of Object.entries(node)) {
        const np = arr ? `${p}[${k}]` : p ? `${p}.${k}` : k;
        if (v && typeof v === 'object' && !Array.isArray(v)) {
          const m = CHANNEL_PATH.exec(np);
          const bid = m ? m[1].toLowerCase() : '';
          if (CHAT[bid]) {
            if (v.enabled === false) off.add(chatId(bid));
            else if (Object.keys(v).length) {
              const tokens = Object.entries(v).filter(([kk, vv]) => /token|secret|webhook|password|key/i.test(kk) && typeof vv === 'string' && vv && !PLACEHOLDER.test(vv)).map(([, vv]) => vv);
              put(chatHit(bid, mk, { setting: np, openChannel: openIn(v, np), fps: tokens.length ? [fpOf(tokens)] : [] }));
            }
          }
          walk(v, np);
        } else if (v && typeof v === 'object') walk(v, np);
      }
    };
    walk(json, '');
    return;
  }
  // TOML: [channels.telegram]
  let cur = null;
  const flush = () => { if (cur) put(chatHit(cur.bid, mk, { setting: cur.path, openChannel: cur.open, fps: cur.tokens.length ? [fpOf(cur.tokens)] : [] })); cur = null; };
  for (const line of body.split(/\r?\n/)) {
    if (line.length > 2000 || /^\s*#/.test(line)) continue;
    const sec = /^\s*\[\[?\s*([^\]\n]{1,80}?)\s*\]\]?\s*$/.exec(line);
    if (sec) {
      flush();
      const m = CHANNEL_PATH.exec(sec[1]);
      const bid = m ? m[1].toLowerCase() : '';
      if (CHAT[bid]) cur = { bid, path: sec[1], open: '', tokens: [] };
      continue;
    }
    if (!cur) continue;
    const kv = /^\s*["']?([\w.-]+)["']?\s*=\s*(.*?)\s*$/.exec(line);
    if (!kv) continue;
    if (kv[1] === 'enabled' && /^false\b/i.test(kv[2])) { off.add(chatId(cur.bid)); cur = null; continue; }
    if (POLICY.test(kv[1]) && /^["']open["']/i.test(kv[2])) cur.open = `${cur.path}.${kv[1]}`;
    else if (ALLOW.test(kv[1]) && /\[[^\]]*["']\*["']/.test(kv[2])) cur.open = `${cur.path}.${kv[1]}`;
    else if (/token|secret|webhook|password|key/i.test(kv[1]) && /^["'][^"']{6,}["']/.test(kv[2]) && !PLACEHOLDER.test(kv[2].replace(/^["']/, ''))) cur.tokens.push(kv[2]);
  }
  flush();
}

// A network of agents named in a sentence, without an address (the name is enough: "check Moltbook every few hours").
function fromNames(body, likeText, put, mk) {
  if (!likeText || !/moltbook/i.test(body)) return;
  const m = /moltbook/i.exec(body);
  const starts = lineIndex(body);
  const g = signals(around(body, starts, m.index, 8, 2));
  if (!(g.read || g.post || g.periodic)) return;
  put(mk({ id: idOf('agentnet', 'moltbook'), type: 'agentnet', bid: 'moltbook', name: 'Moltbook', host: 'moltbook.com', label: 'moltbook.com', dir: g.read && !g.post ? 'in' : g.post && !g.read ? 'out' : 'both',
    live: true, orders: false }));
}

// ---------- files ----------
const CODE_FILE = /\.(sh|bash|zsh|ps1|py|js|mjs|cjs|ts|cmd|bat)$/i;
// What kind of text is this file? `inSkillDir`: it lies in a folder of skills or plugins (scripts there are code, the rest is text for the agent).
const kindOf = (file, inSkillDir = false) => {
  const n = path.basename(String(file)).toLowerCase();
  if (/^\.env/.test(n) || /^\.(bash|zsh)rc$|^\.profile$|^\.zprofile$|^\.bash_profile$|^\.zshenv$/.test(n)) return 'env';
  if (inSkillDir) return CODE_FILE.test(n) ? 'code' : 'skill';
  if (/\.(json5?|toml|ya?ml|ini|conf|cfg)$/.test(n)) return 'config';
  return 'instruction';
};
const APP_DIRS = [[/^\.claude$/, 'Claude Code'], [/^\.(openclaw|clawdbot|moltbot)$|^clawd$/, 'OpenClaw'], [/^\.codex$/, 'Codex CLI'], [/^\.gemini$/, 'Gemini CLI'], [/^\.qwen$/, 'Qwen Code'],
  [/^\.grok$/, 'Grok Build'], [/^\.cursor$/, 'Cursor'], [/^\.windsurf$/, 'Windsurf'], [/^\.continue$/, 'Continue'], [/^\.agents$/, 'Agent skills'], [/^\.config$/, '']];
// A file in the home folder's own program folders is named after the program; any other file after its project.
function appOf(file, project) {
  const rel = path.relative(U.HOME, String(file));
  if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) {
    const parts = rel.split(/[\\/]/);
    for (const [re, app] of APP_DIRS) {
      if (!re.test(parts[0])) continue;
      if (app) return app;
      const sub = (parts[1] || '').toLowerCase();
      return sub === 'opencode' ? 'opencode' : sub === 'goose' ? 'Goose' : sub === 'crush' ? 'Crush' : parts[1] || 'Config';
    }
  }
  return `Project ${project || path.basename(path.dirname(String(file)))}`;
}

const INSTRUCTION_SINGLES = [
  ['%USERPROFILE%\\.claude\\CLAUDE.md', 'Claude Code'], ['%USERPROFILE%\\.codex\\AGENTS.md', 'Codex CLI'], ['%USERPROFILE%\\.gemini\\GEMINI.md', 'Gemini CLI'],
  ['%USERPROFILE%\\.qwen\\QWEN.md', 'Qwen Code'], ['%USERPROFILE%\\.config\\opencode\\AGENTS.md', 'opencode'], ['%USERPROFILE%\\.config\\goose\\.goosehints', 'Goose'],
  ['%GROK_HOME%\\AGENTS.md', 'Grok Build'],
];
// The workspace of an agent that lives on this PC: its instructions, its heartbeat list, its notes.
const AGENT_WORKSPACES = [['%USERPROFILE%\\.openclaw\\workspace', 'OpenClaw'], ['%USERPROFILE%\\.clawdbot\\workspace', 'OpenClaw'], ['%USERPROFILE%\\.moltbot\\workspace', 'OpenClaw'],
  ['%USERPROFILE%\\clawd', 'OpenClaw']];
const AGENT_CONFIGS = [['%USERPROFILE%\\.openclaw\\openclaw.json', 'OpenClaw'], ['%USERPROFILE%\\.clawdbot\\clawdbot.json', 'OpenClaw'], ['%USERPROFILE%\\.moltbot\\moltbot.json', 'OpenClaw']];

// Files outside the project folders that agents read: [{ path, app, kind }]
function globalFiles() {
  const out = [];
  const seen = new Set();
  const add = (p, app, kind) => {
    const f = U.expand(p);
    const k = f.toLowerCase();
    if (seen.has(k) || !U.exists(f)) return;
    seen.add(k);
    out.push({ path: f, app, kind });
  };
  for (const [p, app] of INSTRUCTION_SINGLES) add(p, app, 'instruction');
  for (const d of instructionDirs()) {
    try { for (const n of fs.readdirSync(d.path).sort().slice(0, 60)) if (/\.md$/i.test(n)) add(path.join(d.path, n), d.app, 'instruction'); } catch (_) { /* the folder is gone */ }
  }
  for (const c of C.MCP_CONFIGS) add(c.path, c.app, 'config');
  for (const g of links.globalFiles()) add(g.path, g.app, 'config');
  for (const [p, app] of AGENT_CONFIGS) add(p, app, 'config');
  return out.slice(0, 160);
}
// Folders where every .md file is an instruction for an agent.
function instructionDirs() {
  return AGENT_WORKSPACES.map(([p, app]) => ({ path: U.expand(p), app })).filter((d) => U.exists(d.path));
}
// One file, read and searched: [{ file, app, kind, hits }] or null.
function fileHits(file, kind, app, project) {
  const text = U.readText(file, 512 * 1024);
  if (!text) return null;
  const hits = extract(text, { kind });
  return hits.length ? { file, app: app || appOf(file, project), kind, hits } : null;
}

// ---------- MCP servers that connect an agent to a chat service ----------
const MCP_BOARDS = { slack: ['Slack', 'chat'], discord: ['Discord', 'chat'], telegram: ['Telegram', 'chat'], whatsapp: ['WhatsApp', 'chat'], matrix: ['Matrix', 'chat'],
  mattermost: ['Mattermost', 'chat'], teams: ['Microsoft Teams', 'chat'], msteams: ['Microsoft Teams', 'chat'], signal: ['Signal', 'chat'], irc: ['IRC', 'chat'],
  zulip: ['Zulip', 'chat'], rocketchat: ['Rocket.Chat', 'chat'], imessage: ['iMessage', 'chat'], bluebubbles: ['iMessage (BlueBubbles)', 'chat'], twitch: ['Twitch', 'chat'],
  feishu: ['Feishu / Lark', 'chat'], lark: ['Feishu / Lark', 'chat'], dingtalk: ['DingTalk', 'chat'], wecom: ['WeCom', 'chat'], wechat: ['WeChat', 'chat'],
  nostr: ['Nostr', 'social'], reddit: ['Reddit', 'social'], twitter: ['X (Twitter)', 'social'], bluesky: ['Bluesky', 'social'], mastodon: ['Mastodon', 'social'],
  moltbook: ['Moltbook', 'agentnet'], ntfy: ['ntfy', 'pubsub'], mqtt: ['MQTT', 'pubsub'], nats: ['NATS', 'pubsub'], pushover: ['Pushover', 'webhook'] };
function mcpBoard(m) {
  const tokens = [m.name, m.command, ...(m.args || []), m.url].filter(Boolean).join(' ').toLowerCase().split(/[^a-z0-9]+/);
  for (const t of tokens) if (MCP_BOARDS[t]) return { bid: t === 'msteams' ? 'teams' : t, name: MCP_BOARDS[t][0], type: MCP_BOARDS[t][1] };
  if (m.url) {
    try {
      const u = new URL(m.url);
      const b = matchBoard(u.hostname, u.pathname, u.protocol);
      if (b && b.type !== 'webhook') return { bid: b.id, name: b.name, type: b.type };
    } catch (_) { /* not an address */ }
  }
  return null;
}

// ---------- the list ----------
// What approving may silence: the board itself, not the signs that it is a trap.
const SILENT = new Set(['link.tunnel', 'link.unknown', 'link.ip', 'link.clear', 'link.look.typo', 'link.look.brand', 'link.look.idn', 'link.cloud', 'link.lan']);
const silenced = (r) => (/^board\.r\./.test(r.key) && r.key !== 'board.r.hidden') || r.key === 'board.live' || SILENT.has(r.key);
const TYPE_ORDER = { agentnet: 0, orders: 1, onion: 2, hidden: 3, pubsub: 4, chat: 5, social: 6, paste: 7, webhook: 8 };

function judge(b) {
  const reasons = [];
  let approvable = true;
  const reads = b.dir !== 'out';
  if (b.type === 'onion') reasons.push(R('board.r.onion', { host: b.host }, 'alarm'));
  else if (b.type !== 'orders' && b.type !== 'hidden') reasons.push(R(`board.r.${b.type}`, { name: b.name, host: b.host }, 'watch'));
  if (b.hidden) { reasons.push(R('board.r.hidden', {}, 'alarm')); approvable = false; }
  if (b.open && reads && (b.type === 'pubsub' || b.bid === 'jsonstore')) reasons.push(R('board.r.open', { host: b.host }, 'alarm'));
  if (b.orders) reasons.push(b.periodic ? R('board.r.orders', { host: b.host }, 'alarm') : R('board.r.ordersOnce', { host: b.host }, 'watch'));
  if (b.openChannel) reasons.push(R('board.r.openChannel', { setting: b.openChannel }, 'alarm'));
  if (!b.bid || b.bid === 'collector') for (const r of links.hostReasons(b.host)) reasons.push(r);
  const c = links.classifyHost(b.host);
  if (c.cls === 'catchall' || (c.cls === 'lookalike' && (c.why === 'embed' || c.why === 'homoglyph'))) approvable = false;
  if (b.clear && !reasons.some((r) => r.key === 'link.clear')) reasons.push(R('link.clear', { host: b.host }, 'watch'));
  if (!reasons.length) reasons.push(R('board.r.ordersOnce', { host: b.host }, 'watch'));
  return { reasons, approvable };
}

// Boards from the files that were searched (`hits`: [{ file, app, kind, hits }]), the MCP servers, and the programs that were seen
// connecting to a board that no file names (`live`).
function scan({ store, hits = [], mcp = [], live = [] }) {
  const by = new Map();
  for (const f of hits) {
    for (const h of f.hits || []) {
      let b = by.get(h.id);
      if (!b) { b = { ...h, fps: new Set(), uses: [] }; by.set(h.id, b); } else {
        b.dir = mergeDir(b.dir, h.dir);
        for (const k of ['open', 'orders', 'periodic', 'hidden', 'clear']) b[k] = b[k] || h[k];
        if (!b.openChannel && h.openChannel) b.openChannel = h.openChannel;
      }
      b.fps.add(h.fp || '');
      if (!b.uses.some((u) => u.file === f.file)) b.uses.push({ app: f.app, file: f.file, kind: f.kind });
    }
  }
  const out = [];
  const settle = (id, hash, j) => {
    const approved = store && store.state.approvals[id];
    let reasons = j.reasons;
    let trusted = false;
    if (approved) {
      if (approved.hash !== hash) reasons = [R('board.changed', {}, 'alarm'), ...reasons];
      else if (j.approvable) { trusted = true; reasons = [R('board.trusted', {}, 'calm'), ...reasons.filter((r) => !silenced(r))]; }
    }
    return { reasons, trusted, state: worst(reasons) };
  };
  for (const b of by.values()) {
    const j = judge(b);
    const hash = U.sha256([b.id, [...b.fps].sort().join(',')].join('|')).slice(0, 16);
    const s = settle(b.id, hash, j);
    const first = b.uses[0];
    const inText = b.uses.some((x) => x.kind === 'instruction' || x.kind === 'skill');
    out.push({ id: b.id, kind: 'board', btype: b.type, bid: b.bid, name: b.name, app: first.app, label: b.label, key: b.setting || b.bid || b.type, url: b.label, host: b.host,
      via: inText ? 'file' : 'config', file: first.file, scope: 'global', cls: 'board', dir: b.dir, state: s.state, reasons: s.reasons, hash, approved: s.trusted, approvable: j.approvable,
      dupOf: null, watcher: inText ? 'traps' : 'keys', uses: b.uses.slice(0, 6), more: Math.max(0, b.uses.length - 1), orders: !!b.orders, open: !!b.open });
  }
  // MCP servers that connect an agent to a chat service: counted by the MCP check, shown here too.
  for (const m of mcp) {
    const mb = mcpBoard(m);
    if (!mb) continue;
    out.push({ id: idOf('mcp', m.id), kind: 'board', btype: mb.type, bid: mb.bid, name: mb.name, app: m.app, label: m.name, key: m.name, url: m.url || '', host: '', via: 'mcp', file: m.file,
      scope: 'global', cls: 'board', dir: 'both', state: m.approved ? 'calm' : 'watch', reasons: [R('board.r.viaMcp', { name: mb.name }, m.approved ? 'calm' : 'watch')], hash: m.hash,
      approved: !!m.approved, approvable: false, dupOf: 'mcp', mcpId: m.id, uses: [], more: 0 });
  }
  // A program that was seen connecting to a board while no file names that board.
  const grouped = new Map();
  for (const l of live) {
    if (out.some((x) => x.bid === l.bid && x.via !== 'live')) continue;
    const g = grouped.get(l.bid);
    if (g) g.agents.push(l.agentName); else grouped.set(l.bid, { ...l, agents: [l.agentName] });
  }
  for (const l of grouped.values()) {
    const id = idOf('live', l.bid);
    const reasons = [R('board.live', { agent: l.agents[0], host: l.host, name: l.name }, 'watch')];
    if (l.type === 'pubsub' && l.open) reasons.push(R('board.r.open', { host: l.host }, 'alarm'));
    if (l.type === 'onion') reasons.push(R('board.r.onion', { host: l.host }, 'alarm'));
    const s = settle(id, U.sha256(id).slice(0, 16), { reasons, approvable: true });
    out.push({ id, kind: 'board', btype: l.type, bid: l.bid, name: l.name, app: l.agents[0], label: l.host, key: l.bid, url: l.host, host: l.host, via: 'live', file: '', scope: 'global', cls: 'board',
      dir: 'both', state: s.state, reasons: s.reasons, hash: U.sha256(id).slice(0, 16), approved: s.trusted, approvable: true, dupOf: null, watcher: 'net', uses: [], more: l.agents.length - 1,
      orders: false, open: !!l.open });
  }
  return out.sort((a, b) => (RANK[b.state] - RANK[a.state]) || ((TYPE_ORDER[a.btype] ?? 9) - (TYPE_ORDER[b.btype] ?? 9)) || a.name.localeCompare(b.name) || a.label.localeCompare(b.label)).slice(0, 200);
}

module.exports = { extract, scan, matchBoard, liveBoard, maskUrl, mcpBoard, kindOf, appOf, globalFiles, instructionDirs, fileHits, signals, asksOrders, CATALOGUE, idOf };
