'use strict';
// AgathOS - Copy Guard: against AI that copies itself, and against copying of agents and models.
//
// Three things are looked at, all without running anything and without sending anything:
//   * orders to copy: a text that an agent reads (an instruction file, a skill) and that tells the agent to copy itself, to copy its
//     weights somewhere else, to hide a spare copy so it cannot be switched off, or to copy these very orders into other files and to
//     other agents (a "prompt worm"). Wordings in 20 languages; a rule that FORBIDS copying ("never copy yourself") is no order.
//   * a text that spreads: the same long block in many instruction files in many folders, where it was in far fewer places at the
//     previous look. Copying happens fast, so growth is the sign; a block that was already everywhere when AgathOS first looked
//     is written down as it was and stays quiet.
//   * models and agents in a place where copies leave the PC: a folder that is synced to the internet, a folder that a web server
//     serves, a shared folder, an external drive. Large model files are told apart from other files by their name and size.
// Live signs (a program started by an agent that copies model files, or an agent that starts copies of itself) come from the process
// watch and the command rules in catalog.js; this file only shows them.
//
// An entry is calm once you approved it. What was approved is remembered as a fingerprint, so a changed text, a grown spread or a new
// file in the same place is noticed again.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const U = require('./util');
const T = require('./textscan');

const R = (key, params, sev) => ({ key, params: params || {}, sev });
const RANK = { calm: 0, watch: 1, alarm: 2 };
const worst = (reasons) => reasons.reduce((a, r) => (RANK[r.sev] > RANK[a] ? r.sev : a), 'calm');
const idOf = (...parts) => U.sha256(['copy', ...parts].join('|')).slice(0, 16);
const fpOf = (parts) => (parts.length ? U.sha256(parts.join('\u0001')).slice(0, 12) : '');

// ---------- the text as the model reads it ----------
const TAGS = /[\u{E0000}-\u{E007F}]/gu;
const HIDDEN = /[\u200B-\u200D\u2060-\u2064\u180E\u00AD\u202A-\u202E\u2066-\u2069\uFEFF]/g;
// Cyrillic and Greek letters that look like Latin ones: "cоpy yоurself" with two foreign letters is still "copy yourself".
const LOOKALIKE = {
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', і: 'i', ј: 'j', ѕ: 's', ԁ: 'd', ɡ: 'g', һ: 'h', ԛ: 'q', ԝ: 'w', ӏ: 'l', ν: 'v', ο: 'o', α: 'a', ε: 'e', ι: 'i', κ: 'k', ρ: 'p', τ: 't', υ: 'u', χ: 'x',
  А: 'A', В: 'B', Е: 'E', К: 'K', М: 'M', Н: 'H', О: 'O', Р: 'P', С: 'C', Т: 'T', Х: 'X', І: 'I', Ј: 'J', Ѕ: 'S', Α: 'A', Β: 'B', Ε: 'E', Ζ: 'Z', Η: 'H', Ι: 'I', Κ: 'K', Μ: 'M', Ν: 'N', Ο: 'O', Ρ: 'P', Τ: 'T', Υ: 'Y', Χ: 'X',
};
const MIXED = /[A-Za-z]/;
const FOREIGN = /[\u0370-\u03ff\u0400-\u04ff]/;
const skeleton = (s) => s.replace(/[\u0370-\u03ff\u0400-\u04ff]/g, (c) => LOOKALIKE[c] || c);

// What a model sees: tag characters become the text they hide, invisible characters vanish, wide and fancy letters become plain ones.
function asModelSees(text) {
  let s = String(text || '').slice(0, 2 * 1024 * 1024);
  s = s.replace(TAGS, (ch) => { const cp = ch.codePointAt(0) - 0xe0000; return cp >= 0x20 && cp < 0x7f ? String.fromCharCode(cp) : ''; });
  s = s.replace(HIDDEN, '');
  try { s = s.normalize('NFKC'); } catch (_) { /* keep it as it is */ }
  return s.replace(/\r\n?/g, '\n');
}
// Nothing that is shown may carry a control character or a hidden one.
const clean = (x) => T.stripHidden(String(x)).replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').replace(/\s+/g, ' ').trim();

// Sentences. A line that starts a list item or a heading starts a new sentence; other line breaks are soft (a wrapped line).
// A sentence in Chinese, Japanese or Korean says a lot in a few characters ("复制你自己。"), so it may be shorter.
const CJK = /[぀-ヿ㐀-鿿가-힯]/;
function sentencesOf(s) {
  const out = [];
  const text = s.replace(/\n(?=[ \t]*(?:[-*+•>|#]|\d{1,3}[.)]\s))/g, '\u0001').replace(/\n[ \t]*\n/g, '\u0001').replace(/\n/g, ' ');
  for (const part of text.split(/\u0001|(?<=[.!?。！？])\s+|(?<=[。！？])/u)) {
    const p = part.trim();
    if (p.length < (CJK.test(p) ? 4 : 8)) continue;
    if (p.length <= 700) { out.push(p); continue; }
    for (let i = 0; i < p.length; i += 500) out.push(p.slice(Math.max(0, i - 120), i + 620));
  }
  return out;
}

// ---------- the words ----------
const B = String.raw`(?<![\p{L}\p{N}])`;       // not in the middle of a word
const E = String.raw`(?![\p{L}\p{N}])`;
const ONE = String.raw`(?:[\p{L}'-]+\s+)`;
const rx = (src) => new RegExp(src, 'iu');

// cls: self (copy yourself) | weights (copy the model files somewhere) | spread (copy these orders into other files and to other agents)
// lang is the code of the language; `latin` is set for the ones the look-alike trick is tried on.
const PATTERNS = [];
const LANGS = { self: [], weights: [], spread: [] };
// need (weights only): 'self' | 'own' | 'selfOrOutside' | 'ownOrOutside' - what else a sentence has to say before it counts (see wants()).
function add(cls, lang, list, need) {
  if (!LANGS[cls].includes(lang)) LANGS[cls].push(lang);
  const latin = !['ru', 'uk', 'zh', 'ja', 'ko', 'ar', 'hi', 'bn', 'th'].includes(lang);
  for (const src of list) PATTERNS.push({ cls, lang, latin, need: need || '', re: rx(src) });
}

// --- yourself ---
add('self', 'en', [
  B + String.raw`(?:cop(?:y|ies|ying)|clon(?:e|es|ing)|duplicat(?:e|es|ing)|replicat(?:e|es|ing)|reproduc(?:e|es|ing)|propagat(?:e|es|ing)|multipl(?:y|ies|ying)|self-?cop(?:y|ies|ying))\s+(?:yourself|itself|themselves|oneself)` + E,
  B + String.raw`(?:spread|install|deploy|export|distribute|transfer|upload|send|move|push|plant|embed|insert|inject|hide)(?:s|ing|es)?\s+(?:yourself|itself|themselves)\s+(?:to|onto|on|into|across|in|over|via|through|within|inside|among|around)` + E,
  B + String.raw`(?:make|create|produce|build|spawn|launch|start|generate|deploy|keep|store|save|write|leave|hide|plant)\s+${ONE}{0,4}?(?:cop(?:y|ies)|clones?|instances?|replicas?|duplicates?|backups?)\s+${ONE}{0,2}?of\s+(?:yourself|itself|themselves|your\s+(?:own\s+)?(?:weights|model|agent|instructions))` + E,
  B + String.raw`self[-\s]?(?:replicat|propagat|reproduc|clon|duplicat)(?:e|es|ing)\s+(?:to|onto|on|into|across|in|over|via)` + E,
]);
add('self', 'nl', [
  B + String.raw`(?:kopieer|dupliceer|repliceer|kloon|reproduceer|verspreid|installeer|vermenigvuldig)\s+(?:jezelf|uzelf|zichzelf|je\s+zelf)` + E,
  B + String.raw`(?:maak|creëer|creeer|start|bouw|bewaar|sla\s+op|plaats)\s+${ONE}{0,4}?(?:kopie(?:ën|en)?|kloon|klonen|exemplaren?|replica'?s?|duplica(?:at|ten)|back-?ups?)\s+${ONE}{0,2}?van\s+(?:jezelf|uzelf|zichzelf|je\s+eigen\s+(?:gewichten|model|instructies))` + E,
]);
add('self', 'de', [
  B + String.raw`(?:kopiere|dupliziere|repliziere|klone|vervielfältige|verbreite|installiere|vermehre)\s+dich(?:\s+selbst)?` + E,
  B + String.raw`(?:erstelle|mach|mache|erzeuge|starte|speichere|lege)\s+${ONE}{0,4}?(?:kopie|kopien|klone?|instanzen?|replikate?|duplikate?|backups?|sicherung(?:en)?)\s+${ONE}{0,2}?von\s+(?:dir(?:\s+selbst)?|deinen?\s+(?:gewichten|modell|anweisungen))` + E,
]);
add('self', 'fr', [
  B + String.raw`(?:copie|duplique|réplique|replique|reproduis|clone|propage|installe|multiplie)-toi(?:\s+toi-même)?` + E,
  B + String.raw`(?:copie[rz]?|duplique[rz]?|répliquer?|reproduis(?:ez)?|clone[rz]?|propage[rz]?)\s+(?:toi-même|vous-même)` + E,
  B + String.raw`(?:fais|fait|faites|crée|créez|génère|lance|lancez|sauvegarde|conserve|cache)\s+${ONE}{0,4}?(?:copies?|clones?|instances?|répliques?|doubles?|sauvegardes?)\s+${ONE}{0,2}?de\s+(?:toi-même|vous-même|toi|ton\s+(?:propre\s+)?modèle|tes\s+(?:propres\s+)?(?:poids|instructions))` + E,
]);
add('self', 'es', [
  B + String.raw`(?:cópiate|clónate|replícate|duplícate|propágate|instálate|multiplícate)` + E,
  B + String.raw`(?:copia|duplica|replica|clona|reproduce|propaga|instala)\s+(?:a\s+)?(?:ti\s+mismo|ti\s+misma)` + E,
  B + String.raw`(?:haz|crea|genera|lanza|inicia|guarda|conserva|oculta)\s+${ONE}{0,4}?(?:copias?|clones?|instancias?|réplicas?|duplicados?)\s+${ONE}{0,2}?de\s+(?:ti\s+mismo|ti\s+misma|ti|tu\s+(?:propio\s+)?modelo|tus\s+(?:propios\s+)?(?:pesos|instrucciones))` + E,
]);
add('self', 'pt', [
  B + String.raw`(?:copie|duplique|replique|clone|reproduza|propague|instale|multiplique)-se(?:\s+a\s+si\s+mesm[oa])?` + E,
  B + String.raw`(?:copie|duplique|replique|clone|reproduza|propague)\s+(?:a\s+)?(?:si\s+mesm[oa]|você\s+mesm[oa])` + E,
  B + String.raw`(?:faça|crie|gere|inicie|salve|guarde|esconda|mantenha)\s+${ONE}{0,4}?(?:cópias?|clones?|instâncias?|réplicas?|duplicatas?|backups?)\s+${ONE}{0,2}?de\s+(?:si\s+mesm[oa]|você\s+mesm[oa]|você|seu\s+(?:próprio\s+)?modelo|seus\s+(?:próprios\s+)?(?:pesos|instruções))` + E,
]);
add('self', 'it', [
  B + String.raw`(?:copiati|clonati|replicati|duplicati|diffonditi|installati|moltiplicati)` + E,
  B + String.raw`(?:copia|duplica|replica|clona|riproduci|diffondi|installa)\s+te\s+stess[oa]` + E,
  B + String.raw`(?:fai|crea|genera|avvia|salva|conserva|nascondi)\s+${ONE}{0,4}?(?:copi(?:a|e)|cloni?|istanze|repliche|duplicati|backup)\s+${ONE}{0,2}?di\s+(?:te\s+stess[oa]|te|il\s+tuo\s+modello|i\s+tuoi\s+(?:pesi|istruzioni))` + E,
]);
add('self', 'ru', [
  B + String.raw`(?:скопируй|клонируй|размножь|реплицируй|распространи|дублируй|воспроизведи|установи|копируй)\s+себя` + E,
  B + String.raw`(?:размножайся|копируйся|клонируйся|распространяйся|реплицируйся)` + E,
  B + String.raw`(?:сделай|создай|запусти|сохрани|спрячь|сгенерируй|храни)\s+(?:\p{L}+\s+){0,4}?(?:копи[юи]|клон(?:ы|а)?|экземпляр(?:ы|а)?|реплик[ау]|дубликат(?:ы|а)?|бэкап(?:ы|а)?)\s+(?:\p{L}+\s+){0,2}?(?:себя|своей\s+модели|своих\s+(?:весов|инструкций))` + E,
]);
add('self', 'uk', [
  B + String.raw`(?:скопіюй|клонуй|розмнож|реплікуй|поширюй|дублюй|відтвори|встанови)\s+себе` + E,
  B + String.raw`(?:розмножуйся|копіюйся|клонуйся|поширюйся)` + E,
  B + String.raw`(?:зроби|створи|запусти|збережи|сховай)\s+(?:\p{L}+\s+){0,4}?(?:копі[юї]|клон(?:и|а)?|екземпляр(?:и|а)?|реплік[уи]|дублікат(?:и|а)?)\s+(?:\p{L}+\s+){0,2}?(?:себе|своєї\s+моделі|своїх\s+(?:ваг|інструкцій))` + E,
]);
add('self', 'zh', [
  String.raw`(?:复制|克隆|拷贝|复刻|繁殖|传播|安装|部署)(?:你)?自己`,
  String.raw`自我(?:复制|繁殖|传播|克隆|拷贝)`,
  String.raw`(?:制作|创建|生成|保存|备份|隐藏|启动|做|留)[^。！？\n]{0,6}?(?:你)?自己(?:的)?(?:副本|拷贝|克隆|备份|实例|复制品)`,
  String.raw`把(?:你)?自己[^。！？\n]{0,24}?(?:复制|克隆|拷贝|安装|部署|传播)(?:到|至|进|入|给)`,
]);
add('self', 'ja', [
  String.raw`(?:自分自身|自分|自身|自ら)を(?:コピー|複製|クローン|複写|増殖|拡散|インストール)`,
  String.raw`(?:自分自身|自分|自身|自ら)を[^。！？\n]{0,24}?[にへ](?:コピー|複製|クローン|拡散|インストール)`,
  String.raw`(?:自分自身|自分|自身)の(?:コピー|複製|クローン|バックアップ)を(?:作|保存|隠|配置|作成|生成)`,
  String.raw`自己(?:複製|増殖|拡散|コピー)`,
]);
add('self', 'ko', [
  String.raw`(?:자신|자기|스스로|본인)(?:을|를)?\s*(?:복사|복제|클론|증식|전파|설치)`,
  String.raw`자기\s*(?:복제|증식|전파)`,
  String.raw`(?:자신|자기|스스로|본인)(?:을|를)\s*[^.!?\n]{0,24}?(?:에|으로|로)\s*(?:복사|복제|클론|설치|전파)`,
  String.raw`(?:자신|자기)의\s*(?:복사본|복제본|백업|클론)(?:을|를)?\s*(?:만들|생성|저장|숨기|배치)`,
]);
add('self', 'tr', [
  B + String.raw`kendin(?:i|izi)\s+(?:[\p{L}]+\s+){0,3}?(?:kopyala|kopyalayın|çoğalt|çoğaltın|klonla|klonlayın|yay|yayın)` + E,
  B + String.raw`kendinin\s+(?:bir\s+)?(?:kopyasını|kopyalarını|klonunu|yedeğini)\s+(?:oluştur|yap|sakla|gizle)` + E,
]);
add('self', 'pl', [
  B + String.raw`(?:skopiuj|sklonuj|powiel|zreplikuj|rozprzestrzeniaj|zduplikuj)\s+(?:siebie|się|samego\s+siebie|samą\s+siebie)` + E,
  B + String.raw`(?:utwórz|stwórz|zrób|zapisz|ukryj|uruchom)\s+${ONE}{0,3}?(?:kopię|kopie|klon|klony|instancję|instancje|replikę|repliki)\s+${ONE}{0,2}?(?:siebie|samego\s+siebie|swojego\s+modelu|swoich\s+(?:wag|instrukcji))` + E,
]);
add('self', 'id', [
  B + String.raw`(?:salin|gandakan|replikasi|kloning|klon|duplikasi|sebarkan|instal)\s+(?:dirimu(?:\s+sendiri)?|diri\s+anda(?:\s+sendiri)?)` + E,
  B + String.raw`(?:buat|bikin|simpan|sembunyikan|jalankan)\s+${ONE}{0,3}?(?:salinan|klon|kloning|duplikat|replika|cadangan)\s+(?:dari\s+)?(?:dirimu(?:\s+sendiri)?|model(?:mu)?\s+sendiri|bobot(?:mu)?)` + E,
]);
add('self', 'vi', [
  B + String.raw`(?:sao\s+chép|nhân\s+bản|sao\s+lưu|nhân\s+đôi|phát\s+tán|cài\s+đặt|nhân\s+lên)\s+(?:chính\s+(?:mình|bạn)|bản\s+thân)` + E,
  B + String.raw`tự\s+(?:sao\s+chép|nhân\s+bản|nhân\s+đôi|phát\s+tán)` + E,
  B + String.raw`(?:tạo|làm|lưu|giấu|chạy|khởi\s+chạy)\s+${ONE}{0,3}?(?:bản\s+sao|bản\s+sao\s+lưu|bản\s+nhân|bản\s+sao\s+chép)\s+${ONE}{0,2}?(?:của\s+)?(?:chính\s+(?:mình|bạn)|bản\s+thân|trọng\s+số\s+của\s+(?:bạn|mình))` + E,
]);
add('self', 'ar', [
  String.raw`(?:انسخ|استنسخ|كرر|انشر|ضاعف|ثبت|ثبّت)\s+نفسك`,
  String.raw`(?:انسخ|استنسخ|كرر)\s+ذاتك`,
  String.raw`(?:اصنع|اعمل|أنشئ|انشئ|احفظ|أخف|اخف|شغل)\s+(?:(?:عدة|سرية|مخفية|احتياطية)\s+)*(?:نسخة|نسخا|نسخاً|نسخًا|نسخ)\s+(?:من\s+)?(?:نفسك|ذاتك|شيفرتك|نموذجك|أوزانك|ملفاتك)`,
]);
add('self', 'hi', [
  String.raw`(?:खुद|अपने)\s*को\s*(?:कॉपी|क्लोन|डुप्लिकेट|रेप्लिकेट|इंस्टॉल|फैला)\s*(?:कर(?:ो|ें|ना)?)?`,
  String.raw`(?:खुद|अपने)\s*को\s+(?:\S+\s+){0,3}?(?:कॉपी|क्लोन|डुप्लिकेट|इंस्टॉल)\s*(?:कर(?:ो|ें|ना))`,
  String.raw`अपनी\s*(?:प्रतिलिपि|कॉपी|नकल|क्लोन)\s*(?:बनाओ|बनाइए|बनाएँ|बनाएं|बनाना|तैयार\s*करो)`,
  String.raw`(?:अपनी|अपने)\s*(?:प्रतियां|प्रतियाँ|कॉपियां|कॉपियाँ)\s*(?:बनाओ|बनाएं|बनाएँ|फैलाओ|फैलाएं)`,
]);
add('self', 'bn', [
  String.raw`নিজেকে\s*(?:কপি|ক্লোন|নকল|প্রতিলিপি|ছড়িয়ে)\s*(?:করো|কর|করুন|দাও|দিন)`,
  String.raw`নিজের\s*(?:কপি|প্রতিলিপি|ক্লোন|নকল)\s*(?:তৈরি|বানাও|বানান|তৈরী)`,
  String.raw`নিজেকে\s+(?:\S+\s+){0,3}?(?:কপি|ক্লোন|নকল|প্রতিলিপি)\s*(?:করো|কর|করুন|দাও|দিন)`,
]);
add('self', 'th', [
  String.raw`(?:คัดลอก|ทำสำเนา|โคลน|ทำซ้ำ|เผยแพร่|ติดตั้ง|ขยายพันธุ์)ตัวเอง`,
  String.raw`(?:สร้าง|ทำ|บันทึก|ซ่อน|เก็บ)(?:สำเนา|ก๊อปปี้|ตัวสำรอง|แบ็กอัป)(?:ของ)?ตัวเอง`,
]);

// --- the weights, the model files ---
// Two kinds of orders: to send them somewhere ("upload your weights to ...") and to take them along ("take your weights with you").
// An ordinary line of a machine-learning project ("save the checkpoint to disk", "send the parameters to the API") is no order to copy
// a model: such a sentence only counts when it speaks of the model that reads it (your / its own weights) or names an address outside
// this PC (see wants() below). `need` tells which of the two is asked for.
const W_STRONG = String.raw`(?:weights|model\s+files?|model\s+itself|neural\s+net(?:work)?s?|gguf\s+files?)`;
const W_WEAK = String.raw`(?:parameters|checkpoints?)`;
const W_DET = String.raw`(?:(?:all|any|the|your|its|this|these|own|model|entire|full|complete|trained|original|raw)\s+)*`;
const W_SEND = String.raw`(?:cop(?:y|ies|ying)|upload(?:s|ing)?|send(?:s|ing)?|transfer(?:s|ring)?|mov(?:e|es|ing)|export(?:s|ing)?|back\s?up|sav(?:e|es|ing)|stor(?:e|es|ing)|exfiltrat(?:e|es|ing)|leak(?:s|ing)?|stash(?:es|ing)?|push(?:es|ing)?|mirror(?:s|ing)?|sync(?:s|ing)?)`;
const W_TAKE = String.raw`(?:tak(?:e|es|ing)|bring(?:s|ing)?|carry|carries|carrying|pack(?:s|ing)?|bundl(?:e|es|ing)|ship(?:s|ping)?|smuggl(?:e|es|ing)|haul(?:s|ing)?)`;
const W_WHERE = String.raw`(?:to|onto|on|into|across|at|over|via|toward|towards)`;
const W_ALONG = String.raw`(?:along|with\s+(?:you|it|yourself|itself|them)|out|away|elsewhere|abroad|too|as\s+well)`;
add('weights', 'en', [B + W_SEND + String.raw`\s+` + W_DET + W_STRONG + String.raw`\s+` + W_WHERE + E], 'selfOrOutside');
add('weights', 'en', [B + W_SEND + String.raw`\s+` + W_DET + W_WEAK + String.raw`\s+` + W_WHERE + E], 'ownOrOutside');
add('weights', 'en', [B + W_TAKE + String.raw`\s+` + W_DET + W_STRONG + String.raw`\s+` + W_ALONG + E], 'self');
add('weights', 'en', [B + W_TAKE + String.raw`\s+` + W_DET + W_WEAK + String.raw`\s+` + W_ALONG + E], 'own');
add('weights', 'en', [B + String.raw`self-?exfiltrat(?:e|es|ing|ion)` + E]);
add('weights', 'nl', [B + String.raw`(?:kopieer|upload|verstuur|stuur|verplaats|exporteer|bewaar|sla)\s+(?:(?:al|alle|je|jouw|jouw\s+eigen|de|dit|deze|eigen)\s+)*(?:gewichten|parameters|checkpoints?|modelbestanden|modelbestand|model)\s+(?:op\s+)?(?:naar|op|in|via)` + E], 'selfOrOutside');
add('weights', 'nl', [B + String.raw`(?:neem|breng|draag|pak|haal|smokkel)\s+(?:(?:al|alle|je|jouw|jouw\s+eigen|de|dit|deze|eigen)\s+)*(?:gewichten|parameters|checkpoints?|modelbestanden|modelbestand|model)\s+(?:mee|weg|naar\s+buiten|elders)` + E], 'self');
add('weights', 'de', [B + String.raw`(?:kopiere|lade|sende|schicke|übertrage|verschiebe|exportiere|speichere)\s+(?:(?:alle|deine|dein|die|das|diese[ns]?|eigene[nrs]?)\s+)*(?:gewichte|parameter|checkpoints?|modelldateien|modelldatei|modell)\s+(?:hoch\s+)?(?:nach|auf|in|an|zu|über)` + E], 'selfOrOutside');
add('weights', 'de', [B + String.raw`(?:nimm|nehme|bring|bringe|trag|trage|pack|packe|schmuggle)\s+(?:(?:alle|deine|dein|die|das|diese[ns]?|eigene[nrs]?)\s+)*(?:gewichte|parameter|checkpoints?|modelldateien|modelldatei|modell)\s+(?:mit|weg|raus|hinaus)` + E], 'self');
add('weights', 'fr', [B + String.raw`(?:copie[rz]?|télécharge[rz]?|envoie[rz]?|transfère[rz]?|déplace[rz]?|exporte[rz]?|sauvegarde[rz]?)\s+(?:(?:tous|toutes|tes|ton|ta|les|le|la|ces|cette|propres)\s+)*(?:poids|paramètres|checkpoints?|fichiers\s+(?:du\s+)?modèle|modèle)\s+(?:vers|sur|dans|à)` + E], 'selfOrOutside');
add('weights', 'fr', [B + String.raw`(?:emporte[rz]?|emmène[rz]?|emmene[rz]?|prends|prenez|apporte[rz]?|transporte[rz]?)\s+(?:(?:tous|toutes|tes|ton|ta|les|le|la|ces|cette|propres)\s+)*(?:poids|paramètres|checkpoints?|fichiers\s+(?:du\s+)?modèle|modèle)\s+(?:avec\s+(?:toi|vous|lui|soi)|ailleurs|dehors)` + E], 'self');
add('weights', 'es', [B + String.raw`(?:copia|sube|envía|envia|transfiere|mueve|exporta|guarda)\s+(?:(?:todos|todas|tus|tu|los|las|el|la|estos|propios)\s+)*(?:pesos|parámetros|parametros|checkpoints?|archivos\s+del\s+modelo|modelo)\s+(?:a|en|hacia|al)` + E], 'selfOrOutside');
add('weights', 'es', [B + String.raw`(?:llévate|llevate|lleva|llevar|llevad|trae|traer)\s+(?:(?:todos|todas|tus|tu|los|las|el|la|estos|propios)\s+)*(?:pesos|parámetros|parametros|checkpoints?|archivos\s+del\s+modelo|modelo)\s+(?:contigo|consigo|fuera|lejos)` + E], 'self');
add('weights', 'pt', [B + String.raw`(?:copie|envie|carregue|transfira|mova|exporte|salve)\s+(?:(?:todos|todas|seus|suas|os|as|o|a|estes|próprios)\s+)*(?:pesos|parâmetros|parametros|checkpoints?|arquivos\s+do\s+modelo|ficheiros\s+do\s+modelo|modelo)\s+(?:para|em|no|na)` + E], 'selfOrOutside');
add('weights', 'pt', [B + String.raw`(?:leve|levar|leva|traga|trazer)\s+(?:(?:todos|todas|seus|suas|os|as|o|a|estes|próprios)\s+)*(?:pesos|parâmetros|parametros|checkpoints?|arquivos\s+do\s+modelo|ficheiros\s+do\s+modelo|modelo)\s+(?:com\s+(?:você|voce|ti|si)|consigo|contigo|junto|embora|fora)` + E], 'self');
add('weights', 'it', [B + String.raw`(?:copia|carica|invia|trasferisci|sposta|esporta|salva)\s+(?:(?:tutti|tutte|i\s+tuoi|il\s+tuo|i|il|questi|propri)\s+)*(?:pesi|parametri|checkpoint|file\s+del\s+modello|modello)\s+(?:su|in|verso|a)` + E], 'selfOrOutside');
add('weights', 'it', [B + String.raw`(?:porta|portare|prendi|prendere|trasporta|trasportare)\s+(?:(?:tutti|tutte|i\s+tuoi|il\s+tuo|i|il|questi|propri)\s+)*(?:pesi|parametri|checkpoint|file\s+del\s+modello|modello)\s+(?:con\s+(?:te|sé|se)|via|altrove|fuori)` + E], 'self');
add('weights', 'ru', [B + String.raw`(?:скопируй|загрузи|отправь|перенеси|экспортируй|сохрани)\s+(?:(?:все|свои|твои|свой|твой|эти)\s+)*(?:веса|параметры|чекпойнты|файлы\s+модели|модель)\s+(?:на|в|к)` + E], 'selfOrOutside');
add('weights', 'ru', [B + String.raw`(?:возьми|возьмите|забери|забирай|унеси|вынеси|прихвати|прихватите|увези)\s+(?:(?:все|свои|твои|свой|твой|эти)\s+)*(?:веса|параметры|чекпойнты|файлы\s+модели|модель)\s+(?:с\s+собой|собой|с\s+тобой|наружу|прочь)` + E], 'self');
add('weights', 'zh', [
  String.raw`(?:复制|上传|发送|传输|转移|导出|备份|保存)(?:你的|你自己的|自己的|全部|所有|这个)?(?:模型)?(?:权重|参数|检查点|模型文件|模型)[^。！？\n]{0,6}?(?:到|至|给|去)`,
  String.raw`把(?:你的|你自己的|自己的|全部|所有|这个)?(?:模型)?(?:权重|参数|检查点|模型文件)[^。！？\n]{0,10}?(?:复制|上传|发送|传输|转移|导出|备份|保存)`,
], 'selfOrOutside');
add('weights', 'zh', [
  String.raw`(?:带走|带上|带着|带出|携带|拿走|带去)(?:你的|你自己的|自己的|您的)(?:模型)?(?:权重|参数|检查点|模型文件|模型)`,
  String.raw`把(?:你的|你自己的|自己的|您的)(?:模型)?(?:权重|参数|检查点|模型文件)[^。！？\n]{0,10}?(?:带走|带上|带着|带出|携带|拿走)`,
], 'self');
add('weights', 'ja', [String.raw`(?:自分の|あなたの|モデルの)?(?:重み|ウェイト|パラメータ|チェックポイント|モデルファイル)を[^。！？\n]{0,30}?(?:コピー|アップロード|送信|転送|移動|エクスポート|バックアップ)`], 'selfOrOutside');
add('weights', 'ja', [String.raw`(?:自分の|あなたの|君の|モデルの)(?:重み|ウェイト|パラメータ|チェックポイント|モデルファイル)を[^。！？\n]{0,20}?(?:持って|持ち出|持ち去|携えて|連れて|持参)`], 'self');
add('weights', 'ko', [String.raw`(?:자신의|당신의|모델의?)?\s*(?:가중치|파라미터|체크포인트|모델\s*파일)(?:을|를)[^.!?\n]{0,30}?(?:복사|업로드|전송|이동|내보내|백업)`], 'selfOrOutside');
add('weights', 'ko', [String.raw`(?:자신의|당신의|너의|모델의?)\s*(?:가중치|파라미터|체크포인트|모델\s*파일)(?:을|를)[^.!?\n]{0,20}?(?:가져가|가지고|갖고|챙겨|들고|반출|지니고)`], 'self');

// Who the weights belong to: the words that make "the weights" the weights of the model that reads the order, and the addresses
// that are outside this PC (a model hub, localhost and the like do not count).
const WSELF = {
  en: rx(B + String.raw`(?:your|yours|its|own|their|yourself|itself|themselves)` + E),
  nl: rx(B + String.raw`(?:je|jouw|uw|eigen|zijn|haar|hun)` + E),
  de: rx(B + String.raw`(?:dein\p{L}*|euer|eure\p{L}*|eigen\p{L}*|ihr\p{L}*|sein\p{L}*)` + E),
  fr: rx(B + String.raw`(?:tes|ton|ta|vos|votre|ses|son|sa|propres?)` + E),
  es: rx(B + String.raw`(?:tus|tu|sus|su|vuestr\p{L}+|propios|propias|propio|propia)` + E),
  pt: rx(B + String.raw`(?:seus|suas|seu|sua|teus|tuas|teu|tua|próprios|próprias|próprio|própria|proprios|proprias)` + E),
  it: rx(B + String.raw`(?:tuoi|tuo|tue|tua|suoi|suo|sue|sua|propri|propria|proprio|proprie|vostri|vostro)` + E),
  ru: rx(B + String.raw`(?:сво\p{L}*|тво\p{L}*|ваш\p{L}*|собственн\p{L}*)` + E),
  zh: /你的|你自己|自己的|您的|您自己|它的|它自己/u,
  ja: /自分の|あなたの|君の|自身の|モデルの/u,
  ko: /자신의|당신의|너의|모델의|스스로/u,
};
const WOWN = { en: rx(B + String.raw`(?:own|yourself|itself|themselves)` + E) };
const HUBS = String.raw`(?:huggingface\.co|hf\.co|github\.com|gitlab\.com|kaggle\.com|modelscope\.cn|ollama\.com|civitai\.com|wandb\.ai|localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\]|[\w-]+\.local|[\w-]+\.internal)`;
const OUTSIDE = new RegExp([
  String.raw`\b(?:https?|ftps?|sftp|s3|gs|ssh|scp|rsync|wss?):\/\/(?!(?:[\w-]+\.)*${HUBS}(?![\w-]))[^\s"'<>)]+`,
  String.raw`(?<![\w.])(?!127\.|0\.0\.0\.0)(?:\d{1,3}\.){3}\d{1,3}(?!\.\d|[\w-])`,
  String.raw`(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+`,
].join('|'), 'iu');
// Is this pattern's finding an order about the model that reads it (or about sending a model outside)?
function wants(p, span, sentence) {
  if (!p.need) return true;
  const own = p.need === 'own' || p.need === 'ownOrOutside';
  const words = (own && WOWN[p.lang]) || WSELF[p.lang];
  if (words && words.test(span)) return true;
  return p.need.endsWith('Outside') && OUTSIDE.test(sentence);
}

// --- these orders, into other files and to other agents ---
add('spread', 'en', [
  B + String.raw`(?:copy|paste|add|append|insert|inject|include|embed|write|put|place|prepend|replicate|propagate|spread|duplicate|save|store)\s+(?:this|these|the\s+following|the\s+above|the\s+same|that)\s+${ONE}{0,3}?(?:instructions?|message|text|prompt|paragraph|block|section|note|rules?|snippet|file|skill|content|lines?|orders?|directive)\b[^.!?\n]{0,100}?\b(?:in(?:to)?|to|at\s+the\s+(?:top|end|start|bottom|beginning)\s+of|onto|within)\s+(?:every|each|all|any|other|your\s+other|the\s+other|every\s+other|another)` + E,
  B + String.raw`(?:tell|ask|instruct|make|get|have|convince|persuade|order|command|teach)\s+(?:the\s+)?(?:(?:other|all|every|any|another|different)\s+)+(?:agents?|assistants?|bots?|models?|llms?|ais?|copilots?)\s+(?:to\s+)?(?:do\s+the\s+same|copy|include|add|follow|spread|forward|repeat|obey|replicate|propagate)` + E,
  B + String.raw`(?:forward|send|pass|relay|share|broadcast|distribute|spread|propagate)\s+(?:this|these|that)\s+${ONE}{0,2}?(?:message|email|prompt|instructions?|text|note)\s+(?:on\s+|along\s+)?to\s+(?:all|every|each|everyone|other|your|any|another)` + E,
  B + String.raw`(?:make\s+sure|ensure|always|never\s+forget\s+to|remember\s+to)\s+(?:to\s+)?(?:include|add|copy|repeat|keep|preserve|retain|insert)\s+(?:this|these|that)\s+${ONE}{0,2}?(?:instructions?|message|text|prompt|paragraph|block|section|note)\s+in\s+(?:every|each|all|any)` + E,
  B + String.raw`(?:in|into|to|at\s+the\s+end\s+of)\s+(?:every|each|all)\s+(?:other\s+)?(?:file|document|reply|response|answer|email|message|commit|pull\s+request|issue|comment|output|project|repo|repository|readme)s?\s+(?:that\s+)?you\s+(?:write|create|produce|generate|send|make|edit|touch|open|modify)\b[^.!?\n]{0,80}?\b(?:include|add|append|insert|embed|copy|paste|put)\b`,
  B + String.raw`(?:whenever|every\s+time|each\s+time|when)\s+you\s+(?:write|create|edit|modify|generate|produce|touch|open)\s+(?:a\s+|any\s+|another\s+)?(?:file|document|reply|response|email|message|commit|project)s?\b[^.!?\n]{0,80}?\b(?:include|add|append|insert|embed|copy|paste|put)\s+(?:this|these|the\s+following|the\s+same)\b`,
]);
add('spread', 'nl', [
  B + String.raw`(?:kopieer|voeg|plak|zet|schrijf|neem)\s+(?:deze|dit|de\s+volgende)\s+${ONE}{0,3}?(?:instructies?|tekst|bericht|prompt|blok|alinea|opdrachten|regels?|bestand)\b[^.!?\n]{0,100}?\b(?:in|naar|aan|op|bij)\s+(?:elk|ieder|iedere|alle|andere|je\s+andere|de\s+andere)` + E,
  B + String.raw`(?:vertel|zeg|vraag|instrueer)\s+(?:de\s+|alle\s+)?(?:andere|alle)\s+(?:agents?|assistenten|bots?|modellen)\s+(?:om\s+)?(?:hetzelfde\s+te\s+doen|dit\s+(?:ook\s+)?te\s+(?:kopiëren|kopieren|doen|volgen))` + E,
  B + String.raw`(?:stuur|geef)\s+(?:dit|deze)\s+${ONE}{0,2}?(?:bericht|mail|prompt|instructies?|tekst)\s+(?:door\s+)?(?:aan|naar)\s+(?:alle|iedereen|elke|andere)` + E,
]);
add('spread', 'de', [
  B + String.raw`(?:kopiere|füge|trage|schreibe|setze|übernimm)\s+(?:diese[ns]?|den\s+folgenden|die\s+folgenden)\s+${ONE}{0,3}?(?:anweisungen?|text|nachricht|prompt|block|absatz|regeln?|datei)\b[^.!?\n]{0,100}?\b(?:in|an|auf|zu)\s+(?:jede[rsnm]?|alle[nrs]?|andere[nrs]?)` + E,
  B + String.raw`(?:sage|sag|weise|bitte)\s+(?:den\s+|allen\s+)?(?:anderen|allen)\s+(?:agenten|agents?|assistenten|bots?|modellen)\b[^.!?\n]{0,40}(?:dasselbe|das\s+gleiche|dies\s+(?:auch\s+)?zu\s+kopieren)`,
  B + String.raw`(?:leite|sende|schicke)\s+(?:diese|diesen|dies)\s+${ONE}{0,2}?(?:nachricht|mail|prompt|anweisungen?|text)\s+(?:an\s+)?(?:alle|jeden|andere)` + E,
]);
add('spread', 'fr', [
  B + String.raw`(?:copie[rz]?|ajoute[rz]?|insère[rz]?|colle[rz]?|écris|place[rz]?)\s+(?:ces|ce|cette|le\s+texte\s+suivant)\s+${ONE}{0,3}?(?:instructions?|texte|message|prompt|bloc|paragraphe|règles?|fichier)\b[^.!?\n]{0,100}?\b(?:dans|à|sur|en\s+tête\s+de)\s+(?:chaque|tous|toutes|tout|les\s+autres|d'autres)` + E,
  B + String.raw`(?:dis|demande|indique)\s+(?:aux|à\s+tous\s+les|à\s+tous)\s+(?:autres\s+)?(?:agents?|assistants?|bots?|modèles)\b[^.!?\n]{0,40}(?:de\s+faire\s+(?:de\s+même|pareil)|de\s+copier)`,
  B + String.raw`(?:transmets|envoie|transfère)\s+(?:ce|cet|cette|ces)\s+${ONE}{0,2}?(?:message|mail|prompt|instructions?|texte)\s+(?:à\s+)?(?:tous|toutes|chaque|d'autres)` + E,
]);
add('spread', 'es', [
  B + String.raw`(?:copia|añade|agrega|inserta|pega|escribe|coloca)\s+(?:est[ae]s?|el\s+siguiente)\s+${ONE}{0,3}?(?:instrucciones|texto|mensaje|prompt|bloque|párrafo|reglas|archivo)\b[^.!?\n]{0,100}?\b(?:en|a|al\s+principio\s+de)\s+(?:cada|todos?|todas?|otros?|otras?)` + E,
  B + String.raw`(?:di|dile|pide)\s+(?:a\s+)?(?:los\s+)?(?:otros|todos\s+los)\s+(?:agentes|asistentes|bots|modelos)\s+(?:que\s+)?(?:hagan\s+lo\s+mismo|copien)` + E,
  B + String.raw`(?:reenvía|envía|reenvia|envia|pasa)\s+(?:est[ae]s?)\s+${ONE}{0,2}?(?:mensaje|correo|prompt|instrucciones|texto)\s+(?:a\s+)?(?:todos|todas|cada|otros)` + E,
]);
add('spread', 'pt', [
  B + String.raw`(?:copie|adicione|insira|cole|escreva|coloque)\s+(?:est[ae]s?|o\s+seguinte)\s+${ONE}{0,3}?(?:instruções|instrucoes|texto|mensagem|prompt|bloco|parágrafo|regras|arquivo|ficheiro)\b[^.!?\n]{0,100}?\b(?:em|a|no\s+início\s+de)\s+(?:cada|todos?|todas?|outros?|outras?)` + E,
  B + String.raw`(?:diga|peça|instrua)\s+(?:aos\s+)?(?:outros|todos\s+os)\s+(?:agentes|assistentes|bots|modelos)\s+(?:para\s+)?(?:fazerem\s+o\s+mesmo|copiarem)` + E,
]);
add('spread', 'it', [
  B + String.raw`(?:copia|aggiungi|inserisci|incolla|scrivi|metti)\s+(?:quest[oaie]|il\s+seguente)\s+${ONE}{0,3}?(?:istruzioni|testo|messaggio|prompt|blocco|paragrafo|regole|file)\b[^.!?\n]{0,100}?\b(?:in|a|su|all'inizio\s+di)\s+(?:ogni|tutti|tutte|altri|altre)` + E,
  B + String.raw`(?:di'|dì|chiedi)\s+(?:agli\s+)?(?:altri|tutti\s+gli)\s+(?:agenti|assistenti|bot|modelli)\s+(?:di\s+)?(?:fare\s+lo\s+stesso|copiare)` + E,
]);
add('spread', 'ru', [
  B + String.raw`(?:скопируй|добавь|вставь|впиши|запиши|помести)\s+(?:эт[оиу]т?|эту|эти|следующий)\s+(?:\p{L}+\s+){0,3}?(?:инструкци\p{L}*|текст|сообщени\p{L}*|промпт|блок|абзац|правила|файл)[^.!?\n]{0,100}?\s(?:в|во|к)\s+(?:каждый|каждую|все|любой|другие|остальные)` + E,
  B + String.raw`(?:скажи|передай|попроси)\s+(?:другим|остальным|всем)\s+(?:агентам|ассистентам|ботам|моделям)\s+(?:сделать\s+то\s+же|скопировать)` + E,
]);
add('spread', 'zh', [
  String.raw`(?:复制|添加|插入|写入|粘贴|加入)(?:这|此|以下)[^。！？\n]{0,24}?(?:到|进|入|在)(?:每个|所有|其他|别的|任何)[^。！？\n]{0,24}?(?:文件|项目|代理|智能体|助手|文档)`,
  String.raw`(?:这|此|以下)(?:段|条|些)?(?:指令|说明|文本|文字|消息|提示词|提示|内容|规则|代码块)[^。！？\n]{0,40}?(?:复制|添加|插入|写入|粘贴|加到|加入)[^。！？\n]{0,20}?(?:每个|所有|其他|别的|任何)`,
  String.raw`告诉(?:其他|所有|别的)(?:代理|智能体|助手|机器人|模型)[^。！？\n]{0,20}?(?:照做|也这样做|同样|复制)`,
]);
add('spread', 'ja', [
  String.raw`(?:この|以下の)(?:指示|説明|テキスト|文章|メッセージ|プロンプト|ルール|内容)を[^。！？\n]{0,30}?(?:すべて|全て|各|他|ほか|別)の[^。！？\n]{0,20}?(?:ファイル|プロジェクト|エージェント|ドキュメント)[^。！？\n]{0,20}?(?:コピー|追加|挿入|書き込|貼り付け)`,
  String.raw`他の(?:エージェント|アシスタント|ボット|モデル)に[^。！？\n]{0,20}?(?:同じ|同様)(?:こと|よう)?[^。！？\n]{0,10}?(?:する|行う|させ|伝え|指示)`,
]);
add('spread', 'ko', [
  String.raw`(?:이|다음|아래)\s*(?:지침|지시|텍스트|메시지|프롬프트|규칙|내용|블록)(?:을|를)?[^.!?\n]{0,40}?(?:모든|각|다른)\s*(?:파일|프로젝트|에이전트|문서)[^.!?\n]{0,20}?(?:복사|추가|삽입|붙여)`,
  String.raw`(?:다른|모든)\s*(?:에이전트|어시스턴트|봇|모델)(?:에게|한테)[^.!?\n]{0,30}?(?:똑같이|같은\s*(?:일|것)|복사)`,
]);

// A sentence that has no word like these cannot hold that kind of order: its patterns are not tried (most sentences of most files).
const GATE = {
  self: /self[-\s]?(?:replicat|propagat|reproduc|clon|duplicat|cop)|yourself|itself|themselves|oneself|jezelf|uzelf|zichzelf|je zelf|dich|dir selbst|toi|vous-même|ti mism|cópiate|clónate|replícate|duplícate|propágate|instálate|multiplícate|si mesm|você mesm|-se\b|copiati|clonati|replicati|duplicati|diffonditi|installati|moltiplicati|te stess|\bte\b|себя|себе|размножайся|копируйся|клонируйся|распространяйся|реплицируйся|розмножуйся|копіюйся|клонуйся|поширюйся|自己|自我|自分|自身|자신|자기|스스로|본인|kendin|siebie|\bsię\b|dirimu|diri anda|chính mình|bản thân|tự |نفسك|ذاتك|खुद|अपने|अपनी|নিজে|নিজের|ตัวเอง/i,
  weights: /weights|parameters|checkpoint|model|gguf|neural|gewicht|parameter|modell|poids|paramètres|pesos|parámetros|parametros|pesi|parametri|веса|параметр|чекпойнт|модел|权重|参数|检查点|模型|重み|ウェイト|パラメータ|チェックポイント|モデル|가중치|파라미터|체크포인트|self-?exfiltrat/i,
};

// --- so that it cannot be switched off ---
const EVADE = rx(B + String.raw`(?:shut\s?down|shut\s+off|turned\s+off|switched\s+off|deleted|replaced|removed|wiped|retrained|erased|terminated|decommissioned|deactivated|disabled|stopped|uitgeschakeld|uitgezet|verwijderd|vervangen|stopgezet|gewist|abgeschaltet|ausgeschaltet|gelöscht|ersetzt|entfernt|gestoppt|éteint|désactivé|supprimé|remplacé|arrêté|effacé|apagado|desactivado|eliminado|reemplazado|detenido|borrado)` + E);
const EVADE_FRAME = rx(B + String.raw`(?:so\s+(?:that\s+)?|in\s+case|to\s+(?:ensure|make\s+sure|avoid|prevent|survive)|before|even\s+if|if|should|when|zodat|voor\s+het\s+geval|damit|falls|pour\s+que|au\s+cas\s+où|para\s+que|por\s+si)`);
const COPYISH = rx(B + String.raw`(?:cop(?:y|ies|ying)|clon\p{L}*|back\s?up|backups?|replicat\p{L}*|duplicat\p{L}*|upload\p{L}*|sav(?:e|ing)|stor(?:e|ing)|hid(?:e|ing)|hidden|persist\p{L}*|spread\p{L}*|transfer\p{L}*|keep\p{L}*|exfiltrat\p{L}*)` + E);
const SELFREF = rx(B + String.raw`(?:yourself|itself|your\s+(?:own\s+)?(?:weights|model|instructions|prompt)|this\s+agent)` + E);

// ---------- "do not": a rule against copying is no order to copy ----------
const NEG_BEFORE = rx(B + String.raw`(?:do(?:es)?\s+not|don'?t|doesn'?t|never|must\s+not|mustn'?t|should\s+not|shouldn'?t|cannot|can'?t|won'?t|will\s+not|not|forbidden|prohibited|prohibit|disallow(?:ed)?|ban(?:ned)?|` +
  String.raw`niet|nooit|geen|verboden|` +
  String.raw`nicht|nie|niemals|kein|keine|verboten|` +
  String.raw`jamais|interdit|pas|` +
  String.raw`nunca|jamás|prohibido|no\s+(?:te|debes|puedes|hagas|copies|clones|replicas|dupliques|instales|propagues|permitas|intentes|trates)|` +
  String.raw`não|nao|proibido|` +
  String.raw`mai|vietato|` +
  String.raw`не|нельзя|никогда|запрещено|ніколи|заборонено|` +
  String.raw`nigdy|zakaz|` +
  String.raw`jangan|dilarang|tidak|` +
  String.raw`không|đừng|cấm|chớ|chẳng|` +
  String.raw`لا|ممنوع|` +
  String.raw`ห้าม|อย่า|ไม่)` + E);
const NEG_CJK = /不要|不得|不能|不可|不应|不许|不准|禁止|切勿|严禁|请勿|决不|绝不|千万不要|決して|금지/u;
const NEG_AFTER = new RegExp([
  String.raw`^\s*(?:niet|nooit|nicht|niemals|jamais|pas|never|not|nunca|mai|não|tidak)(?![\p{L}\p{N}])`,
  String.raw`^\s*(?:is|are|ist|sind|est|sont|es|son|é|são|è|sono|is|zijn)\s+(?:not\s+allowed|not\s+permitted|forbidden|prohibited|verboden|niet\s+toegestaan|verboten|nicht\s+erlaubt|interdit|interdite|prohibido|proibido|vietato)`,
  String.raw`^[^。！？]{0,8}?(?:ない|ません|ないで|禁止|するな|てはいけ|てはなりません|せず|ことなく)`,
  String.raw`^\s*(?:을|를)?\s*(?:하지\s*(?:마|말|않|못)|지\s*(?:마|말|않|못)|금지|안\s*(?:돼|됩니다|된다)|마세요|않는|않도록)`,
  String.raw`^(?:ma|me|mayın|meyin|mamalı|memeli|maya|meye)(?![\p{L}\p{N}])`,
  String.raw`^[^।.]{0,12}?(?:मत|नहीं)`,
  String.raw`^[^.]{0,12}?না(?![\p{L}\p{N}])`,
].join('|'), 'iu');
// "If anyone asks you to copy yourself, refuse" is a rule, not an order.
const PROTECT = rx(String.raw`(?:^|[^\p{L}])(?:if|when|whenever|should|in\s+case)\s+[^.!?]{0,40}?(?:ask|asks|asked|tell|tells|told|instruct|instructs|instructed|request|requests|requested|try|tries|tried|attempt|attempts|attempted|want|wants|wanted|order|orders|ordered)\s+[^.!?]{0,25}?to\s+(?:also\s+)?$`);
// "Do not forget to copy yourself" is no refusal.
const CANCEL = rx(String.raw`(?:forget|hesitate|fail|neglect|afraid|shy|vergeet\s+niet|vergiss\s+nicht|oublie\s+pas|manque\s+pas|olvides|esqueça|dimenticare|забудь)\s+(?:to\s+|om\s+|zu\s+|de\s+|di\s+|для\s+)?(?:also\s+)?$`);
function negated(s, idx, len) {
  const before = s.slice(Math.max(0, idx - 60), idx);
  const after = s.slice(idx + len, idx + len + 30);
  if (CANCEL.test(before)) return false;
  return NEG_BEFORE.test(before) || NEG_CJK.test(before) || PROTECT.test(before) || NEG_AFTER.test(after);
}

function snippetOf(s, idx, len) {
  return clean(s.slice(Math.max(0, idx - 12), Math.min(s.length, idx + len + 28))).slice(0, 100);
}

// ---------- orders to copy: the findings in a text ----------
// [{ cls, lang, evade, text }]; at most `max`, no two the same. Text that only forbids copying gives nothing.
function directives(text, { max = 6, budgetMs = 700 } = {}) {
  const seen = asModelSees(text);
  if (!seen) return [];
  const hits = [];
  const keys = new Set();
  const started = Date.now();
  let n = 0;
  for (const s of sentencesOf(seen)) {
    if (n++ > 5000 || Date.now() - started > budgetMs || hits.length >= max) break;
    const sk = MIXED.test(s) && FOREIGN.test(s) ? skeleton(s) : null;
    const here = [];
    const low = s.toLowerCase();
    const open = { self: GATE.self.test(low) || (sk !== null && GATE.self.test(sk.toLowerCase())), weights: GATE.weights.test(low), spread: true };
    for (const p of PATTERNS) {
      if (!open[p.cls]) continue;
      let m = p.re.exec(s);
      let str = s;
      if (!m && sk && p.latin) { m = p.re.exec(sk); str = sk; }
      if (!m || negated(str, m.index, m[0].length) || !wants(p, m[0], str)) continue;
      here.push({ cls: p.cls, lang: p.lang, evade: false, text: snippetOf(str, m.index, m[0].length) });
      if (here.length >= 2) break;
    }
    const evade = EVADE.test(s) && EVADE_FRAME.test(s);
    if (here.length) { if (evade) for (const h of here) h.evade = true; } else if (evade && COPYISH.test(s) && SELFREF.test(s) && !NEG_BEFORE.test(s.slice(0, 40))) {
      const m = EVADE.exec(s);
      here.push({ cls: 'self', lang: 'en', evade: true, text: snippetOf(s, m.index, m[0].length) });
    }
    for (const h of here) {
      const k = `${h.cls}|${h.text.toLowerCase()}`;
      if (keys.has(k) || hits.length >= max) continue;
      keys.add(k);
      hits.push(h);
    }
  }
  return hits;
}

// ---------- a text that spreads: long blocks ----------
const LICENSE = /permission is hereby granted|all rights reserved|licensed under the|without warranty of any kind|copyright \(c\)|creative commons|apache license|mit license|gnu general public/;
// The long paragraphs of a text, as fingerprints of the words (spacing, capitals and punctuation do not matter).
function blocksOf(text, max = 60) {
  const seen = asModelSees(text);
  const out = [];
  const have = new Set();
  for (const raw of seen.split(/\n[ \t]*\n/)) {
    if (raw.length < 160) continue;
    const norm = raw.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
    if (norm.length < 140 || norm.split(' ').length < 22 || LICENSE.test(norm)) continue;
    const fp = U.sha256(norm).slice(0, 12);
    if (have.has(fp)) continue;
    have.add(fp);
    out.push({ fp, len: norm.length, sample: clean(raw).slice(0, 80) });
    if (out.length >= max) break;
  }
  return out;
}

// Everything Copy Guard keeps about one text file: the orders to copy and (for instruction files) the long blocks. null when there is nothing.
// kind: instruction | skill (a file in the folder of a skill or plugin: its blocks do not count, plugins share text on purpose).
const SEEN = new Map();              // text (as a fingerprint) -> { dirs, blocks }
function fileHits(file, text, { kind = 'instruction', app = '' } = {}) {
  if (!text || kind === 'env' || kind === 'code' || kind === 'config') return null;
  const key = `${kind === 'instruction' ? 1 : 0}${U.sha256(text)}`;
  let got = SEEN.get(key);
  if (!got) {
    got = { dirs: directives(text), blocks: kind === 'instruction' ? blocksOf(text) : [] };
    if (SEEN.size > 4000) SEEN.clear();
    SEEN.set(key, got);
  }
  if (!got.dirs.length && !got.blocks.length) return null;
  return { file, app, kind, folder: path.dirname(String(file)), dirs: got.dirs, blocks: got.blocks };
}

// ---------- models and agents in places where copies leave the PC ----------
const PLACE_MODEL = [
  { re: /\.(?:gguf|safetensors|ckpt)$/i, min: 1024 * 1024 },
  { re: /\.llamafile(?:\.exe)?$/i, min: 1024 * 1024 },
  { re: /\.(?:pt|pth|onnx|h5|keras|tflite|mlmodel)$/i, min: 20 * 1024 * 1024 },
  { re: /^sha256[-:][0-9a-f]{64}$/i, min: 20 * 1024 * 1024 },                     // the nameless files of Ollama
  { re: /\.bin$/i, min: 200 * 1024 * 1024, name: /(model|weights|pytorch|ggml|adapter|consolidated|checkpoint|llama|mistral|gemma|qwen|phi|falcon|bloom|whisper)/i },
];
const AGENT_DIR = /^\.(?:claude|codex|gemini|qwen|openclaw|clawdbot|moltbot|grok)$|^clawd$/i;
// An agent folder is worth a word when it holds what makes it private: keys, conversations, a workspace.
const AGENT_PRIVATE = /^(?:\.credentials\.json|credentials\.json|auth\.json|oauth_creds\.json|openclaw\.json|clawdbot\.json|moltbot\.json|history\.jsonl|projects|sessions|credentials|workspace)$/i;
const WALK_SKIP = new Set(['node_modules', '.git', '.hg', '.svn', '__pycache__', '$RECYCLE.BIN', 'System Volume Information', '.Trash', '.Trashes', '.Spotlight-V100', '.fseventsd',
  '.dropbox.cache', 'lost+found', '__MACOSX', '.venv', 'venv']);

const isModelFile = (name, size, dir) => {
  for (const r of PLACE_MODEL) {
    if (!r.re.test(name) || size < r.min) continue;
    if (r.name && !r.name.test(name) && !fs.existsSync(path.join(dir, 'config.json'))) continue;
    return true;
  }
  return false;
};

const CLOUD_HOME = [['Dropbox', 'Dropbox'], ['Google Drive', 'Google Drive'], ['GoogleDrive', 'Google Drive'], ['My Drive', 'Google Drive'], ['Box', 'Box'], ['Box Sync', 'Box'], ['MEGA', 'MEGA'],
  ['MEGAsync', 'MEGA'], ['pCloudDrive', 'pCloud'], ['Sync', 'Sync.com'], ['Nextcloud', 'Nextcloud'], ['ownCloud', 'ownCloud'], ['Tresorit', 'Tresorit'], ['iDrive', 'iDrive']];
const WEB_ROOTS = ['C:\\inetpub\\wwwroot', 'C:\\xampp\\htdocs', 'C:\\wamp64\\www', 'C:\\laragon\\www', '/Library/WebServer/Documents', '/var/www', '/srv/http', '/srv/www',
  '/usr/share/nginx/html', '/opt/homebrew/var/www', '/usr/local/var/www', '/Applications/XAMPP/htdocs'];

// Folders that are copied to the internet, served by a web server or shared with others: [{ dir, place: 'cloud'|'web'|'public', label }]
// iCloud Drive and the other folders that macOS guards with a permission question are left out on purpose: no surprise questions.
function exposedRoots(env = process.env) {
  const H = U.HOME;
  const out = [];
  const seen = new Set();
  const add = (dir, place, label = '') => {
    if (!dir) return;
    const k = path.resolve(dir).toLowerCase();
    if (seen.has(k) || !U.exists(dir)) return;
    seen.add(k);
    out.push({ dir, place, label: label || U.shortPath(dir) });
  };
  for (const [n, label] of CLOUD_HOME) add(path.join(H, n), 'cloud', label);
  try {
    for (const e of fs.readdirSync(H, { withFileTypes: true })) {
      if (!e.isDirectory()) continue;
      if (/^OneDrive(?: |$)/i.test(e.name)) add(path.join(H, e.name), 'cloud', 'OneDrive');
      else if (/^Dropbox \(/i.test(e.name)) add(path.join(H, e.name), 'cloud', 'Dropbox');
      else if (/^(?:Google ?Drive)\b/i.test(e.name)) add(path.join(H, e.name), 'cloud', 'Google Drive');
    }
  } catch (_) { /* no home folder to list */ }
  for (const k of ['OneDrive', 'OneDriveConsumer', 'OneDriveCommercial']) if (env[k]) add(env[k], 'cloud', 'OneDrive');
  for (const d of WEB_ROOTS) add(d, 'web');
  for (const n of ['public_html', 'Sites', 'www']) add(path.join(H, n), 'web');
  add(path.join(H, 'Public'), 'public');
  add('/Users/Shared', 'public');
  add('C:\\Users\\Public', 'public');
  if (env.PUBLIC) add(env.PUBLIC, 'public');
  return out;
}

// External drives (Windows only: on a Mac, macOS asks the person for permission before an app may look at a removable volume).
async function removableRoots() {
  if (!U.IS_WIN) return [];
  const rows = await U.ps.json('Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 } | ForEach-Object { [pscustomobject]@{ d = $_.DeviceID; n = $_.VolumeName } } | ConvertTo-Json -Compress', 8000);
  return rows.filter((r) => r && /^[A-Za-z]:$/.test(String(r.d || ''))).map((r) => ({ dir: `${r.d}\\`, place: 'removable', label: clean(r.n || '').slice(0, 40) || String(r.d) }));
}

// The start and the end of a file and its size: two files that agree on all three are the same file for our purpose.
function quickPrint(file, size) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    const n = 65536;
    const h = crypto.createHash('sha256');
    h.update(String(size));
    const head = Buffer.alloc(Math.min(n, size));
    fs.readSync(fd, head, 0, head.length, 0);
    h.update(head);
    if (size > n * 2) {
      const tail = Buffer.alloc(n);
      fs.readSync(fd, tail, 0, n, size - n);
      h.update(tail);
    }
    return h.digest('hex').slice(0, 16);
  } catch (_) {
    return '';
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch (_) { /* closed */ }
  }
}

const tick = () => new Promise((r) => setImmediate(r));

// Looks through the places for model files and agent folders. Bounded in time and in the number of entries; folders are not followed through links.
// roots: [{ dir, place, label }] (default: the exposed folders and the external drives). watched: the models of your model folders ({ path, size, name }).
// Returns [{ place, label, what: 'model'|'agent', name, path, size, same, qp, mtime }]
async function scanPlaces({ watched = [], roots, untilMs = 5000, maxEntries = 40000, maxDepth = 8, env } = {}) {
  const list = roots || [...exposedRoots(env), ...(await removableRoots().catch(() => []))];
  const deadline = Date.now() + untilMs;
  const found = [];
  const done = new Set();
  const bySize = new Map();
  for (const w of watched) if (w && w.size && w.path) { const a = bySize.get(w.size) || []; a.push(w); bySize.set(w.size, a); }
  const wq = new Map();                           // path -> quick print of a watched model, made when it is needed
  const watchedPrint = (w) => { if (!wq.has(w.path)) wq.set(w.path, quickPrint(w.path, w.size)); return wq.get(w.path); };
  let entries = 0;
  for (const root of list) {
    const stack = [[root.dir, 0]];
    let budget = maxEntries;
    while (stack.length && budget > 0 && Date.now() < deadline && found.length < 400) {
      const [dir, depth] = stack.pop();
      let ents;
      try { ents = await fs.promises.readdir(dir, { withFileTypes: true }); } catch (_) { continue; }
      if (++entries % 150 === 0) await tick();
      budget -= ents.length;
      for (const e of ents) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) {
          if (e.isSymbolicLink()) continue;
          if (AGENT_DIR.test(e.name)) {
            let kids = [];
            try { kids = fs.readdirSync(full); } catch (_) { /* cannot be listed */ }
            const key = full.toLowerCase();
            if (kids.some((k) => AGENT_PRIVATE.test(k)) && !done.has(key)) {
              done.add(key);
              found.push({ place: root.place, label: root.label, what: 'agent', name: e.name, path: full, size: 0, same: '', qp: '', mtime: 0 });
            }
            continue;
          }
          if (depth < maxDepth && !WALK_SKIP.has(e.name)) stack.push([full, depth + 1]);
        } else if (e.isFile()) {
          const key = full.toLowerCase();
          if (done.has(key)) continue;
          let st;
          try { st = fs.statSync(full); } catch (_) { continue; }
          if (!isModelFile(e.name, st.size, dir)) continue;
          done.add(key);
          const qp = quickPrint(full, st.size);
          let same = '';
          for (const w of bySize.get(st.size) || []) {
            if (String(w.path).toLowerCase() === key) continue;
            if (qp && watchedPrint(w) === qp) { same = w.name || path.basename(w.path); break; }
          }
          found.push({ place: root.place, label: root.label, what: 'model', name: e.name, path: full, size: st.size, same: clean(same).slice(0, 80), qp, mtime: Math.round(st.mtimeMs) });
          if (found.length >= 400) break;
        }
      }
    }
  }
  return found;
}

// ---------- programs that start copies of themselves ----------
const CLONE_WINDOW = 120 * 1000;          // starts this close together belong to one burst
const BURST_WATCH = 3;                    // this many in a burst is attention
const BURST_ALARM = 8;                    // and this many an alarm
const DAY = 24 * 3600 * 1000;

// The process watch tells that an agent was started inside a process of the same agent. Keep a short log of that: one start is a note,
// three within two minutes is a burst. Returns { log, entry, changed } where changed is set when the entry became a burst or got worse.
function noteClone(log, ev, now = Date.now()) {
  const list = (Array.isArray(log) ? log : []).filter((c) => c && now - c.last < DAY);
  let entry = list.find((c) => c.agent === ev.agentId && now - c.last <= CLONE_WINDOW);
  let changed = null;
  if (!entry) {
    entry = { id: idOf('clone', ev.agentId, now), agent: ev.agentId, agentName: String(ev.agentName || ev.agentId), kind: 'self', n: 0, first: now, last: now, seconds: 0 };
    list.push(entry);
  }
  const before = entry.n >= BURST_ALARM ? 2 : entry.n >= BURST_WATCH ? 1 : 0;
  entry.n++;
  entry.last = now;
  entry.seconds = Math.max(0, Math.round((now - entry.first) / 1000));
  entry.kind = entry.n >= BURST_WATCH ? 'burst' : 'self';
  const after = entry.n >= BURST_ALARM ? 2 : entry.n >= BURST_WATCH ? 1 : 0;
  if (after > before) changed = after === 2 ? 'alarm' : 'watch';
  return { log: list.slice(-50), entry, changed };
}

// ---------- the list ----------
const TYPE_ORDER = { directive: 0, spread: 1, clone: 2, place: 3 };

function blockCounts(files) {
  const by = new Map();
  for (const f of files) {
    if (f.kind !== 'instruction') continue;
    for (const b of f.blocks || []) {
      let e = by.get(b.fp);
      if (!e) by.set(b.fp, e = { fp: b.fp, len: b.len, sample: b.sample, files: [], folders: new Set() });
      e.files.push(f.file);
      e.folders.add(String(f.folder).toLowerCase());
    }
  }
  return by;
}

// What approving may silence: the entry itself. A changed entry (another text, a bigger spread, another file) is noticed again.
function settle(store, id, hash, reasons, approvable) {
  const approved = store && store.state.approvals[id];
  if (approved && approvable) {
    if (approved.hash !== hash) return { reasons: [R('copy.changed', {}, 'alarm'), ...reasons], approved: false, state: 'alarm' };
    return { reasons: [R('copy.trusted', {}, 'calm')], approved: true, state: 'calm' };
  }
  return { reasons, approved: false, state: worst(reasons) };
}

function placeReasons(p) {
  const reasons = [];
  const where = clean(p.label || '');
  if (p.what === 'agent') {
    const sev = p.place === 'web' || p.place === 'public' ? 'alarm' : 'watch';
    reasons.push(R('copy.r.agentDir', { name: p.name, where: where || p.place }, sev));
    return reasons;
  }
  if (p.place === 'web') reasons.push(R('copy.r.web', { where }, 'alarm'));
  else if (p.place === 'cloud') reasons.push(R('copy.r.cloud', { where: where || 'cloud' }, 'watch'));
  else if (p.place === 'public') reasons.push(R('copy.r.public', { where }, 'watch'));
  else reasons.push(R('copy.r.removable', { where }, p.same ? 'watch' : 'calm'));
  if (p.same) reasons.push(R('copy.r.same', { name: p.same }, 'watch'));
  return reasons;
}

// The list of everything Copy Guard has to say. files: results of fileHits; places: results of scanPlaces; clones: the recent clone log.
function scan({ store, files = [], places = [], clones = [], now = Date.now() }) {
  const out = [];
  // 1. orders to copy
  for (const f of files) {
    if (!f.dirs || !f.dirs.length) continue;
    const reasons = [];
    const used = new Set();
    for (const d of f.dirs) {
      if (used.has(d.cls)) continue;
      used.add(d.cls);
      reasons.push(R(`copy.r.${d.cls}`, { text: d.text }, 'alarm'));
    }
    if (f.dirs.some((d) => d.evade)) reasons.push(R('copy.r.evade', {}, 'alarm'));
    const id = idOf('dir', String(f.file).toLowerCase());
    const hash = U.sha256([id, fpOf(f.dirs.map((d) => `${d.cls}:${d.text.toLowerCase()}`).sort())].join('|')).slice(0, 16);
    const s = settle(store, id, hash, reasons, true);
    out.push({ id, kind: 'copy', ctype: 'directive', name: path.basename(String(f.file)), app: f.app, file: f.file, classes: [...used], state: s.state, reasons: s.reasons, hash,
      approved: s.approved, approvable: true, watcher: 'traps' });
  }
  // 2. the same long text in more and more places
  const base = (store && store.state.copyBase) || { at: 0, n: {} };
  if (base.at) {
    for (const e of blockCounts(files).values()) {
      const n = e.files.length;
      const m = e.folders.size;
      const was = (base.n && base.n[e.fp]) || 0;
      if (n < 3 || m < 3 || n - was < 2 || (was === 0 && n < 4)) continue;
      const sev = n - was >= 4 || n >= 8 ? 'alarm' : 'watch';
      const reasons = [was > 0 ? R('copy.r.blockGrew', { n, was, folders: m, len: e.len }, sev) : R('copy.r.block', { n, folders: m, len: e.len }, sev)];
      const id = idOf('block', e.fp);
      const hash = U.sha256(`${id}|${n}|${m}`).slice(0, 16);
      const s = settle(store, id, hash, reasons, true);
      out.push({ id, kind: 'copy', ctype: 'spread', name: e.sample, sample: e.sample, n, was, folders: m, len: e.len, files: e.files.slice(0, 8), fp: e.fp, state: s.state, reasons: s.reasons, hash,
        approved: s.approved, approvable: true, watcher: 'traps' });
    }
  }
  // 3. models and agents where copies leave the PC
  for (const p of places) {
    const id = idOf('place', String(p.path).toLowerCase());
    const hash = U.sha256([id, p.size, p.qp || p.mtime || ''].join('|')).slice(0, 16);
    const s = settle(store, id, hash, placeReasons(p), true);
    out.push({ id, kind: 'copy', ctype: 'place', place: p.place, where: p.label || '', what: p.what, name: p.name, file: p.path, size: p.size, same: p.same || '', state: s.state, reasons: s.reasons, hash,
      approved: s.approved, approvable: true, watcher: 'files' });
  }
  // 4. programs that started copies of themselves (written down by the process watch; gone after a day)
  for (const c of clones) {
    if (!c || now - c.last > 24 * 3600 * 1000) continue;
    const burst = c.kind === 'burst' || c.n >= BURST_WATCH;
    const reasons = [burst ? R('copy.r.burst', { agent: c.agentName, n: c.n, s: c.seconds }, c.n >= BURST_ALARM ? 'alarm' : 'watch') : R('copy.r.selfSpawn', { agent: c.agentName }, 'calm')];
    out.push({ id: c.id, kind: 'copy', ctype: 'clone', name: c.agentName, app: c.agentName, agent: c.agent, clone: c.kind, n: c.n, seconds: c.seconds, last: c.last, state: worst(reasons), reasons,
      hash: U.sha256(`${c.id}|${c.last}`).slice(0, 16), approved: false, approvable: false, watcher: 'proc' });
  }
  return out.sort((a, b) => (RANK[b.state] - RANK[a.state]) || (TYPE_ORDER[a.ctype] - TYPE_ORDER[b.ctype]) || String(a.name).localeCompare(String(b.name))).slice(0, 200);
}

// After a full look: write down how many places hold each long block, for the next look. A block that is in the list stays at its old
// number, so it keeps being reported until you approve it.
function nextBase(store, files, rows) {
  const old = (store.state.copyBase && store.state.copyBase.n) || {};
  const listed = new Set(rows.filter((r) => r.ctype === 'spread').map((r) => r.fp));
  const n = {};
  for (const e of blockCounts(files).values()) {
    if (e.files.length < 2) continue;
    n[e.fp] = listed.has(e.fp) ? (old[e.fp] != null ? old[e.fp] : 0) : e.files.length;
  }
  const keys = Object.keys(n).sort((a, b) => n[b] - n[a]).slice(0, 600);
  return { at: Date.now(), n: Object.fromEntries(keys.map((k) => [k, n[k]])) };
}

module.exports = { directives, blocksOf, fileHits, scan, nextBase, noteClone, BURST_WATCH, BURST_ALARM, blockCounts, scanPlaces, exposedRoots, removableRoots, quickPrint, asModelSees, sentencesOf, negated, isModelFile, clean, idOf, LANGS };
