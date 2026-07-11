const INDEX_PATH = '/index.html';
const SESSION_DAYS = 180;
const ALLOWED_EXTERNAL_ORIGINS = new Set([
  'https://choyuanchang-cloud.github.io',
]);

const STICKERS = [
  ['moon-rabbit', 20], ['strawberry-bear', 22], ['star-dinosaur', 24], ['rainbow-cloud', 26],
  ['smiling-rocket', 28], ['crown-sun', 30], ['planet-cat', 32], ['magic-clock', 35],
  ['tiny-castle', 38], ['comet-fox', 40], ['candy-planet', 42], ['friendly-dragon', 45],
  ['cloud-train', 48], ['telescope-penguin', 50], ['sparkling-backpack', 54], ['smiling-pencil', 58],
  ['moon-explorer', 62], ['tiny-robot', 68], ['time-wizard', 74], ['aurora-whale', 82],
  ['golden-calendar', 90], ['crystal-star', 100], ['dream-crown', 110], ['galaxy-guardian', 120],
].map(([id, cost]) => ({ id, cost }));

let schemaReady;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith('/api/')) {
      if (request.method === 'OPTIONS') {
        return withCors(request, new Response(null, { status: 204 }));
      }

      try {
        await ensureSchema(env);
        return withCors(request, await handleApi(request, env, url));
      } catch (error) {
        console.error(error);
        return withCors(request, json({ error: '系統暫時無法處理，請稍後再試。' }, 500));
      }
    }

    const assetResponse = await env.ASSETS.fetch(request);
    if (assetResponse.status !== 404 || !isPageRequest(request)) {
      return assetResponse;
    }

    const indexUrl = new URL(INDEX_PATH, request.url);
    return env.ASSETS.fetch(new Request(indexUrl, request));
  },
};

async function handleApi(request, env, url) {
  if (url.pathname === '/api/auth/register' && request.method === 'POST') {
    return registerChild(request, env);
  }
  if (url.pathname === '/api/auth/login' && request.method === 'POST') {
    return loginChild(request, env);
  }
  if (url.pathname === '/api/auth/logout' && request.method === 'POST') {
    const auth = await requireChild(request, env);
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(auth.tokenHash).run();
    return json({ ok: true });
  }

  const auth = await requireChild(request, env);
  if (auth instanceof Response) {
    return auth;
  }

  if (url.pathname === '/api/me' && request.method === 'GET') {
    return json(await buildSessionPayload(env, auth.child, undefined));
  }
  if (url.pathname === '/api/attempts' && request.method === 'POST') {
    return recordAttempt(request, env, auth.child);
  }
  if (url.pathname === '/api/progress' && request.method === 'PUT') {
    return saveProgress(request, env, auth.child);
  }
  if (url.pathname === '/api/stickers/redeem' && request.method === 'POST') {
    return redeemSticker(request, env, auth.child);
  }
  if (url.pathname === '/api/records/reset' && request.method === 'POST') {
    return resetRecords(request, env, auth.child);
  }
  if (url.pathname === '/api/leaderboard' && request.method === 'GET') {
    return json({ leaderboard: await getLeaderboard(env, auth.child.id) });
  }

  return json({ error: '找不到這個功能。' }, 404);
}

async function registerChild(request, env) {
  const body = await readJson(request);
  const validation = validateCredentials(body);
  if (validation) return validation;

  const displayName = body.name.trim();
  const nameKey = normalizeName(displayName);
  const existing = await env.DB.prepare('SELECT id FROM children WHERE name_key = ?').bind(nameKey).first();
  if (existing) {
    return json({ error: '這個名字已經有人使用，請改用暱稱。' }, 409);
  }

  const id = crypto.randomUUID();
  const salt = randomToken(16);
  const pinHash = await derivePinHash(body.pin, salt);
  const now = new Date().toISOString();
  const avatarId = `avatar-${hashName(nameKey) % 8}`;
  const progressJson = normalizeProgressJson(body.progress);

  await env.DB.prepare(`
    INSERT INTO children (id, display_name, name_key, pin_salt, pin_hash, avatar_id, progress_json, created_at, last_login_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(id, displayName, nameKey, salt, pinHash, avatarId, progressJson, now, now).run();

  const child = await env.DB.prepare('SELECT * FROM children WHERE id = ?').bind(id).first();
  return json(await buildSessionPayload(env, child, await createSession(env, id)), 201);
}

async function loginChild(request, env) {
  const body = await readJson(request);
  const validation = validateCredentials(body);
  if (validation) return validation;

  const child = await env.DB.prepare('SELECT * FROM children WHERE name_key = ?')
    .bind(normalizeName(body.name))
    .first();
  if (!child || !timingSafeEqual(child.pin_hash, await derivePinHash(body.pin, child.pin_salt))) {
    return json({ error: '名字或數字密碼不正確。' }, 401);
  }

  await env.DB.prepare('UPDATE children SET last_login_at = ? WHERE id = ?')
    .bind(new Date().toISOString(), child.id)
    .run();
  return json(await buildSessionPayload(env, child, await createSession(env, child.id)));
}

async function recordAttempt(request, env, child) {
  const body = await readJson(request);
  if (!body || typeof body.attemptId !== 'string' || typeof body.questionId !== 'string' || typeof body.levelId !== 'string') {
    return json({ error: '作答資料不完整。' }, 400);
  }

  const now = new Date().toISOString();
  const insertAttempt = await env.DB.prepare(`
    INSERT OR IGNORE INTO attempts (id, child_id, question_id, level_id, skill, correct, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(body.attemptId, child.id, body.questionId, body.levelId, String(body.skill ?? ''), body.correct ? 1 : 0, now).run();

  let awarded = 0;
  if (body.correct && Number(insertAttempt.meta?.changes ?? 0) > 0) {
    const pointResult = await env.DB.prepare(`
      INSERT OR IGNORE INTO point_transactions (id, child_id, award_key, kind, delta, created_at)
      VALUES (?, ?, ?, 'correct_answer', 1, ?)
    `).bind(crypto.randomUUID(), child.id, `answer:${body.attemptId}`, now).run();
    awarded = Number(pointResult.meta?.changes ?? 0) > 0 ? 1 : 0;
  }

  const progressJson = normalizeProgressJson(body.progress);
  if (progressJson !== null) {
    await env.DB.prepare('UPDATE children SET progress_json = ? WHERE id = ?').bind(progressJson, child.id).run();
  }

  return json(await buildRewardPayload(env, child.id, awarded));
}

async function saveProgress(request, env, child) {
  const body = await readJson(request);
  const progressJson = normalizeProgressJson(body?.progress);
  if (progressJson === null) return json({ error: '學習紀錄格式不正確。' }, 400);
  await env.DB.prepare('UPDATE children SET progress_json = ? WHERE id = ?').bind(progressJson, child.id).run();
  return json({ ok: true });
}

async function redeemSticker(request, env, child) {
  const body = await readJson(request);
  const sticker = STICKERS.find((item) => item.id === body?.stickerId);
  if (!sticker) return json({ error: '找不到這張貼紙。' }, 404);

  const owned = await env.DB.prepare('SELECT sticker_id FROM child_stickers WHERE child_id = ? AND sticker_id = ?')
    .bind(child.id, sticker.id)
    .first();
  if (owned) return json({ error: '這張貼紙已經在貼紙簿裡了。' }, 409);

  const points = await getPointBalance(env, child.id);
  if (points < sticker.cost) {
    return json({ error: `還差 ${sticker.cost - points} 點才能兌換。` }, 409);
  }

  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare('INSERT INTO child_stickers (child_id, sticker_id, redeemed_at) VALUES (?, ?, ?)')
      .bind(child.id, sticker.id, now),
    env.DB.prepare(`
      INSERT INTO point_transactions (id, child_id, award_key, kind, delta, created_at)
      VALUES (?, ?, ?, 'sticker_redeem', ?, ?)
    `).bind(crypto.randomUUID(), child.id, `redeem:${child.id}:${sticker.id}`, -sticker.cost, now),
  ]);

  return json(await buildRewardPayload(env, child.id, 0));
}

async function resetRecords(request, env, child) {
  const body = await readJson(request);
  const progressJson = normalizeProgressJson(body?.progress);
  if (progressJson === null) return json({ error: '重設資料格式不正確。' }, 400);

  await env.DB.batch([
    env.DB.prepare('DELETE FROM attempts WHERE child_id = ?').bind(child.id),
    env.DB.prepare('DELETE FROM point_transactions WHERE child_id = ?').bind(child.id),
    env.DB.prepare('DELETE FROM child_stickers WHERE child_id = ?').bind(child.id),
    env.DB.prepare('UPDATE children SET progress_json = ? WHERE id = ?').bind(progressJson, child.id),
  ]);
  return json(await buildRewardPayload(env, child.id, 0));
}

async function buildSessionPayload(env, child, sessionToken) {
  return {
    sessionToken,
    child: {
      id: child.id,
      name: child.display_name,
      avatarId: child.avatar_id,
    },
    progress: parseProgress(child.progress_json),
    rewards: await buildRewardPayload(env, child.id, 0),
  };
}

async function buildRewardPayload(env, childId, awarded) {
  const owned = await env.DB.prepare('SELECT sticker_id FROM child_stickers WHERE child_id = ? ORDER BY redeemed_at')
    .bind(childId)
    .all();
  const totalRow = await env.DB.prepare(`
    SELECT COALESCE(SUM(delta), 0) AS points,
           COALESCE(SUM(CASE WHEN delta > 0 THEN delta ELSE 0 END), 0) AS total_points
    FROM point_transactions WHERE child_id = ?
  `).bind(childId).first();
  const weekStart = getWeekStart();
  const weeklyRow = await env.DB.prepare(`
    SELECT COALESCE(SUM(CASE WHEN delta > 0 THEN delta ELSE 0 END), 0) AS weekly_points
    FROM point_transactions WHERE child_id = ? AND created_at >= ?
  `).bind(childId, weekStart).first();

  return {
    awarded,
    points: Number(totalRow?.points ?? 0),
    totalPoints: Number(totalRow?.total_points ?? 0),
    weeklyPoints: Number(weeklyRow?.weekly_points ?? 0),
    ownedStickerIds: (owned.results ?? []).map((row) => row.sticker_id),
    leaderboard: await getLeaderboard(env, childId),
  };
}

async function getLeaderboard(env, currentChildId) {
  const weekStart = getWeekStart();
  const rows = await env.DB.prepare(`
    SELECT c.id, c.display_name, c.avatar_id,
           COALESCE(SUM(CASE WHEN p.delta > 0 AND p.created_at >= ? THEN p.delta ELSE 0 END), 0) AS weekly_points,
           COALESCE(SUM(CASE WHEN p.delta > 0 THEN p.delta ELSE 0 END), 0) AS total_points
    FROM children c
    LEFT JOIN point_transactions p ON p.child_id = c.id
    GROUP BY c.id
    ORDER BY weekly_points DESC, total_points DESC, c.created_at ASC
  `).bind(weekStart).all();

  const ranked = (rows.results ?? []).map((row, index) => ({
    rank: index + 1,
    name: row.display_name,
    avatarId: row.avatar_id,
    weeklyPoints: Number(row.weekly_points ?? 0),
    isCurrentChild: row.id === currentChildId,
  }));
  const current = ranked.find((row) => row.isCurrentChild);
  const top = ranked.slice(0, 10);
  if (current && !top.some((row) => row.isCurrentChild)) top.push(current);
  return top;
}

async function getPointBalance(env, childId) {
  const row = await env.DB.prepare('SELECT COALESCE(SUM(delta), 0) AS points FROM point_transactions WHERE child_id = ?')
    .bind(childId)
    .first();
  return Number(row?.points ?? 0);
}

async function requireChild(request, env) {
  const token = request.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
  if (!token) return json({ error: '請先登入。' }, 401);
  const tokenHash = await sha256(token);
  const child = await env.DB.prepare(`
    SELECT c.* FROM sessions s JOIN children c ON c.id = s.child_id
    WHERE s.token_hash = ? AND s.expires_at > ?
  `).bind(tokenHash, new Date().toISOString()).first();
  return child ? { child, tokenHash } : json({ error: '登入已過期，請重新登入。' }, 401);
}

async function createSession(env, childId) {
  const token = randomToken(32);
  const tokenHash = await sha256(token);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_DAYS * 86400000).toISOString();
  await env.DB.prepare('INSERT INTO sessions (token_hash, child_id, expires_at, created_at) VALUES (?, ?, ?, ?)')
    .bind(tokenHash, childId, expiresAt, now.toISOString())
    .run();
  return token;
}

async function ensureSchema(env) {
  if (!schemaReady) {
    schemaReady = env.DB.batch([
      env.DB.prepare('CREATE TABLE IF NOT EXISTS children (id TEXT PRIMARY KEY, display_name TEXT NOT NULL, name_key TEXT NOT NULL UNIQUE, pin_salt TEXT NOT NULL, pin_hash TEXT NOT NULL, avatar_id TEXT NOT NULL, progress_json TEXT, created_at TEXT NOT NULL, last_login_at TEXT NOT NULL)'),
      env.DB.prepare('CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, child_id TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL)'),
      env.DB.prepare('CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY, child_id TEXT NOT NULL, question_id TEXT NOT NULL, level_id TEXT NOT NULL, skill TEXT NOT NULL, correct INTEGER NOT NULL, created_at TEXT NOT NULL)'),
      env.DB.prepare('CREATE TABLE IF NOT EXISTS point_transactions (id TEXT PRIMARY KEY, child_id TEXT NOT NULL, award_key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, delta INTEGER NOT NULL, created_at TEXT NOT NULL)'),
      env.DB.prepare('CREATE TABLE IF NOT EXISTS child_stickers (child_id TEXT NOT NULL, sticker_id TEXT NOT NULL, redeemed_at TEXT NOT NULL, PRIMARY KEY (child_id, sticker_id))'),
      env.DB.prepare('CREATE INDEX IF NOT EXISTS attempts_child_created_idx ON attempts(child_id, created_at)'),
      env.DB.prepare('CREATE INDEX IF NOT EXISTS points_child_created_idx ON point_transactions(child_id, created_at)'),
      env.DB.prepare('CREATE INDEX IF NOT EXISTS sessions_child_idx ON sessions(child_id)'),
    ]).catch((error) => {
      schemaReady = undefined;
      throw error;
    });
  }
  return schemaReady;
}

function validateCredentials(body) {
  if (!body || typeof body.name !== 'string' || body.name.trim().length < 1 || body.name.trim().length > 12) {
    return json({ error: '請輸入 1 到 12 個字的姓名或暱稱。' }, 400);
  }
  if (typeof body.pin !== 'string' || !/^\d{4,6}$/.test(body.pin)) {
    return json({ error: '數字密碼需要 4 到 6 位數。' }, 400);
  }
  return null;
}

function normalizeProgressJson(progress) {
  if (progress === undefined || progress === null) return null;
  if (typeof progress !== 'object' || !Array.isArray(progress.levelProgress)) return null;
  const serialized = JSON.stringify(progress);
  return serialized.length <= 750000 ? serialized : null;
}

function parseProgress(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  try { return JSON.parse(value); } catch { return null; }
}

async function readJson(request) {
  try { return await request.json(); } catch { return null; }
}

function normalizeName(name) {
  return name.trim().normalize('NFKC').toLocaleLowerCase('zh-Hant');
}

function hashName(value) {
  let hash = 0;
  for (const char of value) hash = ((hash << 5) - hash + char.codePointAt(0)) | 0;
  return Math.abs(hash);
}

async function derivePinHash(pin, salt) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(pin), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: encoder.encode(salt), iterations: 120000 },
    key,
    256,
  );
  return toBase64Url(new Uint8Array(bits));
}

async function sha256(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return toBase64Url(new Uint8Array(digest));
}

function timingSafeEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string' || left.length !== right.length) return false;
  let mismatch = 0;
  for (let index = 0; index < left.length; index += 1) mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return mismatch === 0;
}

function randomToken(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

function toBase64Url(bytes) {
  let binary = '';
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function getWeekStart() {
  const now = new Date();
  const day = now.getUTCDay();
  const diff = day === 0 ? 6 : day - 1;
  now.setUTCDate(now.getUTCDate() - diff);
  now.setUTCHours(0, 0, 0, 0);
  return now.toISOString();
}

function isPageRequest(request) {
  return (request.method === 'GET' || request.method === 'HEAD') && (request.headers.get('accept')?.includes('text/html') ?? false);
}

function json(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

function withCors(request, response) {
  const origin = request.headers.get('origin');
  if (!origin) return response;
  const requestOrigin = new URL(request.url).origin;
  if (origin !== requestOrigin && !ALLOWED_EXTERNAL_ORIGINS.has(origin)) return response;
  const headers = new Headers(response.headers);
  headers.set('access-control-allow-origin', origin);
  headers.set('vary', 'Origin');
  headers.set('access-control-allow-headers', 'Authorization, Content-Type');
  headers.set('access-control-allow-methods', 'GET, POST, PUT, OPTIONS');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
