const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Pool } = require('pg');

const root = __dirname;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined });
const secret = process.env.APP_SECRET;
const json = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(body)); };
const readBody = req => new Promise((resolve, reject) => { let body = ''; req.on('data', c => body += c); req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch { reject(new Error('Invalid JSON')); } }); });
const CHIEF_TOKEN_TTL = 365 * 24 * 60 * 60 * 1000;
const clientIp = req => {
  const forwarded = req.headers['x-forwarded-for'];
  const firstForwarded = (Array.isArray(forwarded) ? forwarded[0] : String(forwarded || '').split(',')[0]).trim();
  return (firstForwarded || req.socket?.remoteAddress || 'unknown').replace(/^::ffff:/, '');
};
const digest = value => crypto.createHmac('sha256', secret).update(value).digest('hex');
const sameDigest = (supplied, expected) => {
  const suppliedBuffer = Buffer.from(String(supplied || ''));
  const expectedBuffer = Buffer.from(String(expected || ''));
  return suppliedBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(suppliedBuffer, expectedBuffer);
};
const ipFingerprint = req => digest(`chief-ip:${clientIp(req)}`).slice(0, 32);
const tokenFor = req => {
  const expiry = String(Date.now() + CHIEF_TOKEN_TTL);
  const fingerprint = ipFingerprint(req);
  return `${expiry}.${fingerprint}.${digest(`${expiry}.${fingerprint}`)}`;
};
const validToken = (token, req) => {
  if (!secret) return false;
  const parts = String(token || '').split('.');
  const expiry = parts[0];
  if (!expiry || !Number.isFinite(Number(expiry)) || Number(expiry) <= Date.now()) return false;
  if (parts.length === 3) {
    const [, fingerprint, signature] = parts;
    return sameDigest(fingerprint, ipFingerprint(req)) && sameDigest(signature, digest(`${expiry}.${fingerprint}`));
  }
  // Accept the previous eight-hour token only long enough to migrate an already-open chief session.
  if (parts.length === 2) return sameDigest(parts[1], digest(expiry));
  return false;
};
const chief = req => validToken(req.headers['x-chief-token'], req);
const ROTATION_NAMES = new Set(['Internal Medicine', 'Night Float', 'Stepdown', 'Cardiology', 'Nephrology', 'Gastroenterology', 'Pulmonology', 'Infectious Disease', 'Neurology', 'ER', 'Elective', 'ICU', 'Rheumatology', 'Hematology', 'Endocrinology', 'Oncology']);
const NAJD_BASELINE = { id: 'r4-najd', name: 'Najd', level: 'R4', endLevel: 'R4', assignments: ['Internal Medicine', 'Internal Medicine', null, null, null, null, 'Stepdown', null, null, null, null, null, null] };
const mergeNajd = (residents, deletedIds = []) => {
  const people = Array.isArray(residents) ? residents.map(person => ({ ...person, assignments: Array.isArray(person.assignments) ? [...person.assignments] : person.assignments })) : [];
  if (deletedIds.includes(NAJD_BASELINE.id)) return people.filter(person => person?.id !== NAJD_BASELINE.id);
  const existingIndex = people.findIndex(person => person?.id === NAJD_BASELINE.id || String(person?.name || '').trim().toLowerCase() === 'najd');
  if (existingIndex >= 0) {
    const existing = people[existingIndex];
    people[existingIndex] = { ...NAJD_BASELINE, ...existing, id: NAJD_BASELINE.id, assignments: Array.isArray(existing.assignments) ? [...existing.assignments, ...Array(13).fill(null)].slice(0, 13) : [...NAJD_BASELINE.assignments] };
    return people;
  }
  const rakanIndex = people.findIndex(person => person?.id === 'r4-rakan');
  people.splice(rakanIndex >= 0 ? rakanIndex + 1 : 0, 0, { ...NAJD_BASELINE, assignments: [...NAJD_BASELINE.assignments] });
  return people;
};
const alignLevels = residents => residents.map(person => ({ ...person, endLevel: person.level }));
const migrateSchedule = state => {
  if (!state || typeof state !== 'object') return state;
  const deletedResidentIds = Array.isArray(state.deletedResidentIds) ? state.deletedResidentIds : [];
  return { ...state, version: Math.max(Number(state.version) || 0, 6), deletedResidentIds, requestedResidents: alignLevels(mergeNajd(state.requestedResidents, deletedResidentIds)), actualResidents: alignLevels(mergeNajd(state.actualResidents, deletedResidentIds)) };
};

const cleanText = (value, fallback = '', max = 80) => {
  const text = String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  return (text || fallback).slice(0, max);
};
const list = value => Array.isArray(value) ? value : [];
const changedSet = (before, after, key) => {
  const oldSet = new Set(list(before?.[key]).map(String));
  const newSet = new Set(list(after?.[key]).map(String));
  return {
    added: [...newSet].filter(value => !oldSet.has(value)).slice(0, 60),
    removed: [...oldSet].filter(value => !newSet.has(value)).slice(0, 60),
  };
};
const compareResidents = (before, after, key, schedule) => {
  const oldPeople = new Map(list(before?.[key]).filter(person => person?.id).map(person => [String(person.id), person]));
  const newPeople = new Map(list(after?.[key]).filter(person => person?.id).map(person => [String(person.id), person]));
  const changes = [];
  for (const [id, person] of newPeople) {
    const previous = oldPeople.get(id);
    if (!previous) continue;
    for (let block = 0; block < 13; block++) {
      const from = list(previous.assignments)[block] || null;
      const to = list(person.assignments)[block] || null;
      if (from === to) continue;
      if (changes.length < 100) changes.push({ schedule, residentId: id, residentName: cleanText(person.name, 'Resident'), level: cleanText(person.level, '', 8), block: block + 1, from, to });
    }
  }
  return {
    count: [...new Set([...oldPeople.keys(), ...newPeople.keys()])].reduce((total, id) => {
      const previous = oldPeople.get(id);
      const person = newPeople.get(id);
      if (!previous || !person) return total;
      return total + Array.from({ length: 13 }, (_, block) => (list(previous.assignments)[block] || null) !== (list(person.assignments)[block] || null)).filter(Boolean).length;
    }, 0),
    changes,
  };
};
const sameJson = (left, right) => JSON.stringify(left ?? null) === JSON.stringify(right ?? null);
const sameSet = (left, right) => {
  const a = new Set(list(left).map(String));
  const b = new Set(list(right).map(String));
  return a.size === b.size && [...a].every(value => b.has(value));
};
const changedObjectKeys = (before, after) => {
  const oldMap = before && typeof before === 'object' ? before : {};
  const newMap = after && typeof after === 'object' ? after : {};
  return [...new Set([...Object.keys(oldMap), ...Object.keys(newMap)])].filter(key => !sameJson(oldMap[key], newMap[key]));
};
const CLIENT_STATE_KEYS = new Set(['version', 'savedAt', 'requestedResidents', 'actualResidents', 'requestMeta', 'deletedResidentIds', 'requestedFundamentalCells', 'actualFundamentalCells', 'theme']);
const topLevelChangesAllowed = (before, after) => changedObjectKeys(before, after).every(key => CLIENT_STATE_KEYS.has(key));
const describeChange = (before, after) => {
  const profileDiffs = [['requestedResidents', 'requested'], ['actualResidents', 'actual']].map(([key, schedule]) => {
    const oldPeople = new Map(list(before?.[key]).filter(person => person?.id).map(person => [String(person.id), person]));
    const newPeople = new Map(list(after?.[key]).filter(person => person?.id).map(person => [String(person.id), person]));
    return {
      added: [...newPeople.keys()].filter(id => !oldPeople.has(id)).map(id => ({ id, name: cleanText(newPeople.get(id)?.name, 'Resident'), level: cleanText(newPeople.get(id)?.level, '', 8), schedule })),
      removed: [...oldPeople.keys()].filter(id => !newPeople.has(id)).map(id => ({ id, name: cleanText(oldPeople.get(id)?.name, 'Resident'), level: cleanText(oldPeople.get(id)?.level, '', 8), schedule })),
      renamed: [...newPeople.keys()].filter(id => oldPeople.has(id) && cleanText(oldPeople.get(id)?.name) !== cleanText(newPeople.get(id)?.name)).map(id => ({ id, from: cleanText(oldPeople.get(id)?.name, 'Resident'), to: cleanText(newPeople.get(id)?.name, 'Resident'), schedule })),
      levelsChanged: [...newPeople.keys()].filter(id => oldPeople.has(id) && oldPeople.get(id)?.level !== newPeople.get(id)?.level).map(id => ({ id, name: cleanText(newPeople.get(id)?.name, 'Resident'), from: cleanText(oldPeople.get(id)?.level, '', 8), to: cleanText(newPeople.get(id)?.level, '', 8), schedule })),
    };
  });
  const unique = (values, keyFor) => [...new Map(values.map(value => [keyFor(value), value])).values()];
  const added = unique(profileDiffs.flatMap(diff => diff.added), item => item.id);
  const removed = unique(profileDiffs.flatMap(diff => diff.removed), item => item.id);
  const renamed = unique(profileDiffs.flatMap(diff => diff.renamed), item => `${item.id}:${item.from}:${item.to}`);
  const levelsChanged = unique(profileDiffs.flatMap(diff => diff.levelsChanged), item => `${item.id}:${item.from}:${item.to}`);
  const requested = compareResidents(before, after, 'requestedResidents', 'requested');
  const actual = compareResidents(before, after, 'actualResidents', 'actual');
  const requestedFundamentals = changedSet(before, after, 'requestedFundamentalCells');
  const actualFundamentals = changedSet(before, after, 'actualFundamentalCells');
  const fundamentalsChanged = requestedFundamentals.added.length + requestedFundamentals.removed.length + actualFundamentals.added.length + actualFundamentals.removed.length;
  const requestMetadataChanged = changedObjectKeys(before?.requestMeta, after?.requestMeta).length;
  const details = {
    requestedAssignmentsChanged: requested.count,
    actualAssignmentsChanged: actual.count,
    assignmentChanges: [...requested.changes, ...actual.changes].slice(0, 100),
    residentsAdded: added.slice(0, 40),
    residentsRemoved: removed.slice(0, 40),
    residentsRenamed: renamed.slice(0, 40),
    residentLevelsChanged: levelsChanged.slice(0, 40),
    requestedFundamentals,
    actualFundamentals,
    requestMetadataChanged,
    themeChanged: Boolean(before && before.theme !== after?.theme),
  };
  const parts = [];
  if (requested.count) parts.push(`${requested.count} requested rotation${requested.count === 1 ? '' : 's'}`);
  if (actual.count) parts.push(`${actual.count} final rotation${actual.count === 1 ? '' : 's'}`);
  const residentChanges = added.length + removed.length + renamed.length + levelsChanged.length;
  if (residentChanges) parts.push(`${residentChanges} resident profile change${residentChanges === 1 ? '' : 's'}`);
  if (fundamentalsChanged) parts.push(`${fundamentalsChanged} fundamental setting${fundamentalsChanged === 1 ? '' : 's'}`);
  if (requestMetadataChanged && !requested.count) parts.push(`${requestMetadataChanged} request submission${requestMetadataChanged === 1 ? '' : 's'}`);
  if (details.themeChanged) parts.push('the shared theme');
  return { details, parts };
};
const inferResidentId = (audit, before, after, details) => {
  const supplied = cleanText(audit?.actorId, '', 100);
  const currentPeople = new Map(list(before?.requestedResidents).filter(person => person?.id).map(person => [String(person.id), person]));
  if (supplied && currentPeople.has(supplied)) return supplied;
  const changedIds = new Set(list(details?.assignmentChanges).filter(change => change.schedule === 'requested').map(change => String(change.residentId)));
  changedObjectKeys(before?.requestMeta, after?.requestMeta).forEach(id => changedIds.add(String(id)));
  return changedIds.size === 1 && currentPeople.has([...changedIds][0]) ? [...changedIds][0] : '';
};
const residentSaveAllowed = (before, after, actorId) => {
  if (!before || !actorId) return false;
  if (!topLevelChangesAllowed(before, after)) return false;
  if (!sameJson(before.actualResidents, after.actualResidents)) return false;
  if (!sameSet(before.deletedResidentIds, after.deletedResidentIds)) return false;
  if (!sameSet(before.requestedFundamentalCells, after.requestedFundamentalCells) || !sameSet(before.actualFundamentalCells, after.actualFundamentalCells)) return false;
  const oldList = list(before.requestedResidents);
  const newList = list(after.requestedResidents);
  const oldIds = oldList.map(person => String(person?.id || ''));
  const newIds = newList.map(person => String(person?.id || ''));
  if (oldIds.length !== newIds.length || new Set(oldIds).size !== oldIds.length || new Set(newIds).size !== newIds.length || oldIds.some((id, index) => !id || id !== newIds[index])) return false;
  const oldPeople = new Map(oldList.map(person => [String(person.id), person]));
  const newPeople = new Map(newList.map(person => [String(person.id), person]));
  if (oldPeople.size !== newPeople.size || !oldPeople.has(actorId) || !newPeople.has(actorId)) return false;
  const fundamentals = new Set(list(before.requestedFundamentalCells).map(String));
  for (const [id, person] of oldPeople) {
    const next = newPeople.get(id);
    if (!next) return false;
    const { assignments: oldAssignmentsValue, ...oldIdentity } = person;
    const { assignments: newAssignmentsValue, ...newIdentity } = next;
    if (!sameJson(oldIdentity, newIdentity)) return false;
    const oldAssignments = list(oldAssignmentsValue);
    const newAssignments = list(newAssignmentsValue);
    for (let block = 0; block < Math.max(13, oldAssignments.length, newAssignments.length); block++) {
      const from = oldAssignments[block] || null;
      const to = newAssignments[block] || null;
      if (from === to) continue;
      if (id !== actorId || block >= 13 || fundamentals.has(`${id}:${block}`) || (to && !ROTATION_NAMES.has(to))) return false;
    }
  }
  return changedObjectKeys(before.requestMeta, after.requestMeta).every(id => id === actorId);
};
const settingsOnlySave = (before, after) => Boolean(before)
  && topLevelChangesAllowed(before, after)
  && sameJson(before.requestedResidents, after.requestedResidents)
  && sameJson(before.actualResidents, after.actualResidents)
  && sameJson(before.requestMeta, after.requestMeta)
  && sameSet(before.deletedResidentIds, after.deletedResidentIds)
  && sameSet(before.requestedFundamentalCells, after.requestedFundamentalCells)
  && sameSet(before.actualFundamentalCells, after.actualFundamentalCells);
const auditIdentity = (req, audit, before, after, details) => {
  if (chief(req)) return { actorType: 'chief', actorId: null, actorName: 'Chief' };
  const actorId = inferResidentId(audit, before, after, details);
  const person = actorId ? new Map(list(before?.requestedResidents).filter(item => item?.id).map(item => [String(item.id), item])).get(actorId) : null;
  if (person) return { actorType: 'resident', actorId, actorName: cleanText(person.name, 'Resident') };
  return { actorType: 'shared', actorId: null, actorName: 'Shared schedule user' };
};
const scheduleSaveAllowed = (req, before, after, identity) => {
  if (chief(req)) return true;
  if (!before) return false;
  if (identity.actorType === 'resident') return residentSaveAllowed(before, after, identity.actorId);
  return settingsOnlySave(before, after);
};
const auditArea = (audit, details) => {
  const allowed = new Set(['requested', 'actual', 'residents', 'fundamentals', 'settings', 'schedule']);
  const requested = cleanText(audit?.area, '', 30);
  if (details.residentsAdded.length || details.residentsRemoved.length || details.residentsRenamed.length || details.residentLevelsChanged.length) return 'residents';
  if (details.requestedFundamentals.added.length || details.requestedFundamentals.removed.length || details.actualFundamentals.added.length || details.actualFundamentals.removed.length) return 'fundamentals';
  if (details.actualAssignmentsChanged && !details.requestedAssignmentsChanged) return 'actual';
  if (details.requestedAssignmentsChanged && !details.actualAssignmentsChanged) return 'requested';
  if (details.themeChanged) return 'settings';
  if (allowed.has(requested)) return requested;
  return 'schedule';
};
const insertAudit = async (client, { revision, actorType, actorId, actorName, area, summary, details }) => {
  await client.query('INSERT INTO schedule_audit(revision,actor_type,actor_id,actor_name,area,summary,details) VALUES($1,$2,$3,$4,$5,$6,$7)', [revision, actorType, actorId, actorName, area, summary, details]);
};
async function init() {
  await pool.query('CREATE TABLE IF NOT EXISTS app_state (key text PRIMARY KEY, value jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(), revision bigint NOT NULL DEFAULT 0)');
  await pool.query('ALTER TABLE app_state ADD COLUMN IF NOT EXISTS revision bigint NOT NULL DEFAULT 0');
  await pool.query("CREATE TABLE IF NOT EXISTS schedule_audit (id bigserial PRIMARY KEY, revision bigint NOT NULL DEFAULT 0, occurred_at timestamptz NOT NULL DEFAULT now(), actor_type text NOT NULL, actor_id text, actor_name text NOT NULL, area text NOT NULL, summary text NOT NULL, details jsonb NOT NULL DEFAULT '{}'::jsonb)");
  await pool.query('CREATE INDEX IF NOT EXISTS schedule_audit_occurred_idx ON schedule_audit (occurred_at DESC)');
}
const server = http.createServer(async (req, res) => {
  try {
    const requestUrl = new URL(req.url, 'http://localhost');
    const pathname = requestUrl.pathname;
    if (pathname === '/api/health') return json(res, 200, { ok: true });
    if (pathname === '/api/schedule' && req.method === 'GET') {
      const r = await pool.query("SELECT value, updated_at, revision FROM app_state WHERE key='schedule'");
      if (!r.rowCount) return json(res, 200, { state: null, revision: 0 });
      const state = migrateSchedule(r.rows[0].value);
      return json(res, 200, { state, savedAt: r.rows[0].updated_at, revision: Number(r.rows[0].revision) });
    }
    if (pathname === '/api/schedule' && req.method === 'PUT') {
      const { state, baseRevision, audit } = await readBody(req);
      if (!state) return json(res, 400, { error: 'Missing schedule.' });
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query("SELECT pg_advisory_xact_lock(hashtext('jhah-schedule'))");
        const current = await client.query("SELECT value, updated_at, revision FROM app_state WHERE key='schedule' FOR UPDATE");
        const currentRevision = current.rowCount ? Number(current.rows[0].revision) : 0;
        if (!Number.isFinite(Number(baseRevision)) || Number(baseRevision) !== currentRevision) {
          await client.query('ROLLBACK');
          const row = current.rows[0];
          return json(res, 409, { error: 'Schedule changed on another device.', state: row ? migrateSchedule(row.value) : null, savedAt: row?.updated_at || null, revision: currentRevision });
        }
        const nextRevision = currentRevision + 1;
        const previousState = current.rowCount ? migrateSchedule(current.rows[0].value) : null;
        let mergedState = migrateSchedule(state);
        let change = describeChange(previousState, mergedState);
        const identity = auditIdentity(req, audit, previousState, mergedState, change.details);
        if (!scheduleSaveAllowed(req, previousState, mergedState, identity)) {
          await client.query('ROLLBACK');
          return json(res, 403, { error: 'Chief access is required for changes outside your requested schedule row.' });
        }
        const residentAssignmentsChanged = identity.actorType === 'resident' && change.details.assignmentChanges.some(item => item.schedule === 'requested' && item.residentId === identity.actorId);
        if (identity.actorType === 'resident' && (residentAssignmentsChanged || !sameJson(previousState?.requestMeta?.[identity.actorId], mergedState?.requestMeta?.[identity.actorId]))) {
          mergedState = { ...mergedState, requestMeta: { ...(mergedState.requestMeta || {}), [identity.actorId]: { editedBy: identity.actorName, editedAt: new Date().toISOString() } } };
          change = describeChange(previousState, mergedState);
        }
        if (!change.parts.length) {
          await client.query('ROLLBACK');
          const row = current.rows[0];
          return json(res, 200, { ok: true, noop: true, state: previousState, revision: currentRevision, savedAt: row?.updated_at || null });
        }
        const area = auditArea(audit, change.details);
        const verb = change.parts.length ? `changed ${change.parts.join(', ')}` : `saved the ${area === 'actual' ? 'final' : area === 'requested' ? 'requested' : 'shared'} schedule without changing a value`;
        const saved = await client.query("INSERT INTO app_state(key,value,revision) VALUES('schedule',$1,$2) ON CONFLICT(key) DO UPDATE SET value=$1, revision=$2, updated_at=now() RETURNING updated_at", [mergedState, nextRevision]);
        await insertAudit(client, { revision: nextRevision, ...identity, area, summary: `${identity.actorName} ${verb}.`, details: change.details });
        await client.query('COMMIT');
        return json(res, 200, { ok: true, state: mergedState, revision: nextRevision, savedAt: saved.rows[0].updated_at });
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    }
    if (pathname === '/api/audit' && req.method === 'GET') {
      if (!chief(req)) return json(res, 401, { error: 'Chief access required.' });
      const limit = Math.min(100, Math.max(1, Math.floor(Number(requestUrl.searchParams.get('limit')) || 50)));
      const result = await pool.query('SELECT id,revision,occurred_at,actor_type,actor_id,actor_name,area,summary,details FROM schedule_audit ORDER BY id DESC LIMIT $1', [limit]);
      const events = result.rows.map(row => ({ id: Number(row.id), revision: Number(row.revision), occurredAt: row.occurred_at, actorType: row.actor_type, actorId: row.actor_id, actorName: row.actor_name, area: row.area, summary: row.summary, details: row.details || {} }));
      return json(res, 200, { events, latestId: events[0]?.id || 0 });
    }
    if (pathname === '/api/chief/login' && req.method === 'POST') { const { password } = await readBody(req); const saved = await pool.query("SELECT value FROM app_state WHERE key='chief_password'"); const current = saved.rowCount ? saved.rows[0].value.password : process.env.CHIEF_PASSWORD; if (!current || !secret || ![current, process.env.MASTER_KEY].includes(password)) return json(res, 401, { error: 'Incorrect password.' }); return json(res, 200, { token: tokenFor(req) }); }
    if (pathname === '/api/chief/session' && req.method === 'GET') {
      if (!chief(req)) return json(res, 401, { error: 'Saved chief access is no longer valid for this network.' });
      return json(res, 200, { ok: true, token: tokenFor(req) });
    }
    if (pathname === '/api/chief/password' && req.method === 'PUT') { if (!chief(req)) return json(res, 401, { error: 'Chief access required.' }); const { password } = await readBody(req); if (!password || password.length < 8) return json(res, 400, { error: 'Password must be at least 8 characters.' }); await pool.query("INSERT INTO app_state(key,value) VALUES('chief_password',$1) ON CONFLICT(key) DO UPDATE SET value=$1", [{ password }]); return json(res, 200, { ok: true }); }
    if (pathname === '/api/baseline/restore' && req.method === 'POST') {
      if (!chief(req)) return json(res, 401, { error: 'Chief access required.' });
      const { state } = await readBody(req);
      if (!state) return json(res, 400, { error: 'Missing baseline schedule.' });
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query("SELECT pg_advisory_xact_lock(hashtext('jhah-schedule'))");
        const current = await client.query("SELECT revision FROM app_state WHERE key='schedule' FOR UPDATE");
        const nextRevision = (current.rowCount ? Number(current.rows[0].revision) : 0) + 1;
        const baselineState = migrateSchedule(state);
        const saved = await client.query("INSERT INTO app_state(key,value,revision) VALUES('schedule',$1,$2) ON CONFLICT(key) DO UPDATE SET value=$1, revision=$2, updated_at=now() RETURNING updated_at", [baselineState, nextRevision]);
        await insertAudit(client, { revision: nextRevision, actorType: 'chief', actorId: null, actorName: 'Chief', area: 'schedule', summary: 'Chief restored the image baseline.', details: { baselineRestored: true } });
        await client.query('COMMIT');
        return json(res, 200, { ok: true, state: baselineState, revision: nextRevision, savedAt: saved.rows[0].updated_at });
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    }
    const file = pathname === '/' ? 'index.html' : decodeURIComponent(pathname.slice(1)); const target = path.resolve(root, file); if (!target.startsWith(root) || !fs.existsSync(target)) return json(res, 404, { error: 'Not found' }); res.writeHead(200, { 'content-type': target.endsWith('.html') ? 'text/html; charset=utf-8' : 'application/octet-stream' }); fs.createReadStream(target).pipe(res);
  } catch (error) { console.error(error); json(res, 500, { error: 'Server error.' }); }
});
init().then(() => server.listen(process.env.PORT || 10000, '0.0.0.0'));
