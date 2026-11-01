var __defProp = Object.defineProperty;

var __name = (target, value) => __defProp(target, "name", { value, configurable: true });



// worker.js

var PREFIX = "ldm:v1:";

var ORIGIN = "https://ligasdetenis.github.io";

var enc = new TextEncoder();

var td = new TextDecoder();

var now =  __name(() => ( new Date()).toISOString(), "now");

var key =  __name((k) => PREFIX + k, "key");

var str =  __name((v, max = 140) => String(v ?? "").trim().slice(0, max), "str");

var id =  __name(() => crypto.randomUUID(), "id");

var b64 =  __name((bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""), "b64");

var unb64 =  __name((value) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=")), (c) => c.charCodeAt(0)), "unb64");

var safeEq =  __name((a, b) => {

  const x = enc.encode(a), y = enc.encode(b);

  let diff = x.length ^ y.length;

  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] || 0) ^ (y[i] || 0);

  return diff === 0;

}, "safeEq");

async function derive(pin, salt) {

  const k = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveBits"]);

  return b64(new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt: unb64(salt), iterations: 1e5, hash: "SHA-256" }, k, 256)));

}

__name(derive, "derive");

async function hashPin(pin) {

  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));

  return { salt, hash: await derive(pin, salt) };

}

__name(hashPin, "hashPin");

function cors(origin) {

  return origin === ORIGIN ? { "Access-Control-Allow-Origin": ORIGIN, "Vary": "Origin", "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Setup-Key", "Access-Control-Allow-Methods": "GET, POST, OPTIONS" } : {};

}

__name(cors, "cors");

function response(data, status = 200, origin = "") {

  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...cors(origin) } });

}

__name(response, "response");

async function read(env, name, fallback) {

  const v = await env.DATA.get(key(name), "json");

  return v ?? fallback;

}

__name(read, "read");

async function put(env, name, val) {

  await env.DATA.put(key(name), JSON.stringify(val));

}

__name(put, "put");

async function signature(secret, data) {

  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);

  return b64(new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(data))));

}

__name(signature, "signature");

async function token(secret, payload) {

  const body = b64(enc.encode(JSON.stringify(payload)));

  return body + "." + await signature(secret, body);

}

__name(token, "token");

async function identity(request, env) {

  const t = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");

  const parts = t.split(".");

  if (parts.length !== 2 || !env.AUTH_SECRET) return null;

  const expected = await signature(env.AUTH_SECRET, parts[0]);

  if (!safeEq(expected, parts[1])) return null;

  let data;

  try {

    data = JSON.parse(td.decode(unb64(parts[0])));

  } catch {

    return null;

  }

  if (data.exp < Date.now() || data.app !== "ldm:v1") return null;

  const users = await read(env, "users", []);

  const user = users.find((x) => x.id === data.id && x.rev === data.rev && x.active);

  return user ? { id: user.id, name: user.name, role: user.role, playerId: user.playerId || null } : null;

}

__name(identity, "identity");

function validPin(pin) {

  return /^\d{6,12}$/.test(String(pin || ""));

}

__name(validPin, "validPin");

function allowAdmin(u) {

  return u && u.role === "admin";

}

__name(allowAdmin, "allowAdmin");

function validDate(v) {

  return /^\d{4}-\d{2}-\d{2}$/.test(str(v, 10)) && !Number.isNaN(Date.parse(v + "T12:00:00Z"));

}

__name(validDate, "validDate");

function validTime(v) {

  return /^([01]\d|2[0-3]):[0-5]\d$/.test(str(v, 5));

}

__name(validTime, "validTime");

function scoreIsValid(s) {

  if (!s || !Array.isArray(s.sets) || s.sets.length !== 2) return false;

  return s.sets.every((p) => Array.isArray(p) && p.length === 2 && p.every((n) => Number.isInteger(n) && n >= 0 && n <= 7) && p[0] !== p[1]);

}

__name(scoreIsValid, "scoreIsValid");

async function handler(req, env) {

  const origin = req.headers.get("Origin") || "";

  if (!env.DATA) return response({ ok: false, error: "Falta binding KV DATA" }, 503, origin);

  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(origin) });

  const url = new URL(req.url), path = url.pathname.replace(/\/$/, "") || "/";

  if (req.method === "GET" && (path === "/" || path === "/health")) return response({ ok: true, app: "Liga Deportiva Militar", service: "ldm-api", version: "1.2.0", kv: "conectado", phase: "nucleo", sharedWithCTCampeador: false }, 200, origin);

  if (!["GET", "POST"].includes(req.method)) return response({ ok: false, error: "M\xE9todo no permitido" }, 405, origin);

  if (origin && origin !== ORIGIN) return response({ ok: false, error: "Origen no autorizado" }, 403, origin);

  const body = req.method === "POST" ? await req.json().catch(() => null) : {};

  if (body === null) return response({ ok: false, error: "JSON incorrecto" }, 400, origin);

  if (!env.AUTH_SECRET || env.AUTH_SECRET.length < 32) return response({ ok: false, error: "Configurar AUTH_SECRET (32 caracteres m\xEDnimo)" }, 503, origin);

  if (path === "/api/setup-status" && req.method === "GET") return response({ ok: true, initialized: (await read(env, "users", [])).length > 0 }, 200, origin);

  if (path === "/api/setup" && req.method === "POST") {

    if (!env.ADMIN_SETUP_KEY || env.ADMIN_SETUP_KEY.length < 20) return response({ ok: false, error: "Configurar ADMIN_SETUP_KEY" }, 503, origin);

    if (!safeEq(req.headers.get("X-Setup-Key") || "", env.ADMIN_SETUP_KEY)) return response({ ok: false, error: "No autorizado" }, 403, origin);

    const users = await read(env, "users", []);

    if (users.length) return response({ ok: false, error: "La configuraci\xF3n inicial ya se complet\xF3" }, 409, origin);

    const name = str(body.name, 80), pin = str(body.pin, 20);

    if (name.length < 2 || !validPin(pin)) return response({ ok: false, error: "Nombre y PIN de 6 a 12 d\xEDgitos obligatorios" }, 400, origin);

    let p;

    try {

      p = await hashPin(pin);

    } catch (e) {

      console.error("LDM SETUP HASH_FAILED", e);

      return response({ ok: false, error: "Error al proteger el PIN. Revisa los logs del Worker.", code: "SETUP_HASH_FAILED" }, 500, origin);

    }

    let user2;

    try {

      user2 = { id: id(), name, role: "admin", active: true, rev: 1, createdAt: now(), ...p };

    } catch (e) {

      console.error("LDM SETUP ID_FAILED", e);

      return response({ ok: false, error: "Error al crear el identificador del administrador.", code: "SETUP_ID_FAILED" }, 500, origin);

    }

    try {

      await put(env, "users", [user2]);

    } catch (e) {

      console.error("LDM SETUP KV_WRITE_FAILED", e);

      return response({ ok: false, error: "Error al guardar el administrador en KV. Revisa permisos y cuota de KV.", code: "SETUP_KV_WRITE_FAILED" }, 500, origin);

    }

    return response({ ok: true, message: "Administrador inicial creado. El setup no permite repetirse." }, 201, origin);

  }

  if (path === "/api/login" && req.method === "POST") {

    const name = str(body.name, 80), pin = str(body.pin, 20);

    if (!name || !validPin(pin)) return response({ ok: false, error: "Credenciales inv\xE1lidas" }, 400, origin);

    const users = await read(env, "users", []);

    const u = users.find((x) => x.name.toLocaleLowerCase("es") === name.toLocaleLowerCase("es") && x.active);

    const salt = u?.salt || b64(new Uint8Array(16));

    const hash = await derive(pin, salt);

    if (!u || !safeEq(hash, u.hash)) return response({ ok: false, error: "Credenciales incorrectas" }, 401, origin);

    return response({ ok: true, token: await token(env.AUTH_SECRET, { app: "ldm:v1", id: u.id, rev: u.rev, exp: Date.now() + 12 * 36e5 }), user: { id: u.id, name: u.name, role: u.role, playerId: u.playerId || null } }, 200, origin);

  }

  const user = await identity(req, env);

  if (!user) return response({ ok: false, error: "Inicia sesi\xF3n" }, 401, origin);

  if (path === "/api/me" && req.method === "GET") return response({ ok: true, user }, 200, origin);

  if (path === "/api/players" && req.method === "GET") return response({ ok: true, players: await read(env, "players", []) }, 200, origin);

  if (path === "/api/matches" && req.method === "GET") return response({ ok: true, matches: await read(env, "matches", []) }, 200, origin);

  if (path === "/api/users" && req.method === "GET") {

    if (!allowAdmin(user)) return response({ ok: false, error: "Solo administraci\xF3n" }, 403, origin);

    return response({ ok: true, users: (await read(env, "users", [])).map(({ salt, hash, ...safe }) => safe) }, 200, origin);

  }

  if (path === "/api/users" && req.method === "POST") {

    if (!allowAdmin(user)) return response({ ok: false, error: "Solo administraci\xF3n" }, 403, origin);

    const name = str(body.name, 80), pin = str(body.pin, 20), role = body.role === "admin" ? "admin" : "player";

    if (name.length < 2 || !validPin(pin)) return response({ ok: false, error: "Nombre y PIN de 6 a 12 d\xEDgitos obligatorios" }, 400, origin);

    const users = await read(env, "users", []);

    if (users.some((x) => x.name.toLocaleLowerCase("es") === name.toLocaleLowerCase("es"))) return response({ ok: false, error: "Usuario ya existente" }, 409, origin);

    const playerId = str(body.playerId || "", 80) || null;

    if (playerId && !(await read(env, "players", [])).some((x) => x.id === playerId)) return response({ ok: false, error: "Jugador no encontrado" }, 400, origin);

    const nu = { id: id(), name, role, playerId, active: true, rev: 1, createdAt: now(), ...await hashPin(pin) };

    users.push(nu);

    await put(env, "users", users);

    return response({ ok: true, user: { id: nu.id, name, role, playerId } }, 201, origin);

  }

  if (path === "/api/players" && req.method === "POST") {

    if (!allowAdmin(user)) return response({ ok: false, error: "Solo administraci\xF3n" }, 403, origin);

    const name = str(body.name, 90), division = str(body.division || "Sub-18", 60);

    if (name.length < 2) return response({ ok: false, error: "Nombre obligatorio" }, 400, origin);

    const players = await read(env, "players", []);

    if (players.some((x) => x.name.toLocaleLowerCase("es") === name.toLocaleLowerCase("es"))) return response({ ok: false, error: "Jugador duplicado" }, 409, origin);

    const player = { id: id(), name, division, createdAt: now() };

    players.push(player);

    await put(env, "players", players);

    return response({ ok: true, player }, 201, origin);

  }

  if (path === "/api/matches" && req.method === "POST") {

    if (!allowAdmin(user)) return response({ ok: false, error: "Solo administraci\xF3n" }, 403, origin);

    const players = await read(env, "players", []), a = str(body.playerAId, 80), b = str(body.playerBId, 80), date = str(body.date, 10), time = str(body.time, 5), court = str(body.court || "", 60);

    if (a === b || !players.some((x) => x.id === a) || !players.some((x) => x.id === b) || !validDate(date) || !validTime(time)) return response({ ok: false, error: "Jugadores, fecha u hora inv\xE1lidos" }, 400, origin);

    const matches = await read(env, "matches", []);

    if (matches.some((m) => m.date === date && m.time === time && ([m.playerAId, m.playerBId].includes(a) || [m.playerAId, m.playerBId].includes(b)))) return response({ ok: false, error: "Un jugador ya tiene partido en esa fecha y hora" }, 409, origin);

    const match = { id: id(), playerAId: a, playerBId: b, date, time, court, status: "scheduled", result: null, history: [], createdAt: now() };

    matches.push(match);

    await put(env, "matches", matches);

    return response({ ok: true, match }, 201, origin);

  }

  if (path === "/api/proposals" && req.method === "GET") {

    const proposals = await read(env, "proposals", []), matches = await read(env, "matches", []);

    const visible = allowAdmin(user) ? proposals : proposals.filter((p) => {

      const m = matches.find((x) => x.id === p.matchId);

      return m && user.playerId && [m.playerAId, m.playerBId].includes(user.playerId);

    });

    return response({ ok: true, proposals: visible }, 200, origin);

  }

  if (path === "/api/proposals" && req.method === "POST") {

    const matchId = str(body.matchId, 80), date = str(body.date, 10), time = str(body.time, 5), court = str(body.court, 60), reason = str(body.reason, 350);

    const matches = await read(env, "matches", []), match = matches.find((m) => m.id === matchId);

    if (!match) return response({ ok: false, error: "Partido no encontrado" }, 404, origin);

    if (match.result || match.status === "played") return response({ ok: false, error: "No se puede reprogramar un partido finalizado" }, 409, origin);

    if (!allowAdmin(user) && (!user.playerId || ![match.playerAId, match.playerBId].includes(user.playerId))) return response({ ok: false, error: "No perteneces a este partido" }, 403, origin);

    if (!validDate(date) || !validTime(time) || !court || reason.length < 3) return response({ ok: false, error: "Fecha, hora, pista y motivo son obligatorios" }, 400, origin);

    if (match.date === date && match.time === time && match.court === court) return response({ ok: false, error: "La propuesta no contiene cambios" }, 400, origin);

    const proposals = await read(env, "proposals", []);

    if (proposals.some((p2) => p2.matchId === match.id && p2.status === "pending")) return response({ ok: false, error: "Ya hay una propuesta pendiente para este partido" }, 409, origin);

    const p = { id: id(), matchId, fromUserId: user.id, fromPlayerId: user.playerId || null, fromName: user.name, createdAt: now(), date, time, court, reason, status: "pending", events: [{ type: "proposed", by: user.id, at: now(), date, time, court, reason }] };

    proposals.push(p);

    await put(env, "proposals", proposals);

    return response({ ok: true, proposal: p }, 201, origin);

  }

  if (path === "/api/proposals/respond" && req.method === "POST") {

    const proposalId = str(body.proposalId, 80), action = str(body.action, 20);

    if (!["accept", "reject", "counter"].includes(action)) return response({ ok: false, error: "Acci\xF3n inv\xE1lida" }, 400, origin);

    const proposals = await read(env, "proposals", []), p = proposals.find((x) => x.id === proposalId);

    if (!p) return response({ ok: false, error: "Propuesta no encontrada" }, 404, origin);

    if (p.status !== "pending") return response({ ok: false, error: "La propuesta ya no est\xE1 pendiente" }, 409, origin);

    const matches = await read(env, "matches", []), m = matches.find((x) => x.id === p.matchId);

    if (!m) return response({ ok: false, error: "Partido inexistente" }, 404, origin);

    if (m.result || m.status === "played") return response({ ok: false, error: "El partido ya est\xE1 finalizado" }, 409, origin);

    if (!allowAdmin(user) && (!user.playerId || ![m.playerAId, m.playerBId].includes(user.playerId))) return response({ ok: false, error: "No perteneces a este partido" }, 403, origin);

    if (p.fromUserId === user.id) return response({ ok: false, error: "No puedes responder a tu propia propuesta" }, 403, origin);

    if (action === "reject") {

      p.status = "rejected";

      p.resolvedAt = now();

      p.resolvedBy = user.id;

      p.events.push({ type: "rejected", by: user.id, at: now() });

      await put(env, "proposals", proposals);

      return response({ ok: true, proposal: p }, 200, origin);

    }

    if (action === "counter") {

      const date = str(body.date, 10), time = str(body.time, 5), court = str(body.court, 60), reason = str(body.reason, 350);

      if (!validDate(date) || !validTime(time) || !court || reason.length < 3) return response({ ok: false, error: "Fecha, hora, pista y motivo son obligatorios" }, 400, origin);

      p.status = "countered";

      p.resolvedAt = now();

      p.resolvedBy = user.id;

      p.events.push({ type: "countered", by: user.id, at: now() });

      const next = { id: id(), matchId: m.id, fromUserId: user.id, fromPlayerId: user.playerId || null, fromName: user.name, createdAt: now(), date, time, court, reason, status: "pending", parentProposalId: p.id, events: [{ type: "proposed", by: user.id, at: now(), date, time, court, reason }] };

      proposals.push(next);

      await put(env, "proposals", proposals);

      return response({ ok: true, proposal: next }, 201, origin);

    }

    if (body.externalCourtConfirmed !== true) return response({ ok: false, error: "Debes confirmar que la pista est\xE1 reservada mediante la m\xE1quina del complejo" }, 400, origin);

    if (matches.some((x) => x.id !== m.id && x.date === p.date && x.time === p.time && !x.result && [x.playerAId, x.playerBId].some((z) => [m.playerAId, m.playerBId].includes(z)))) return response({ ok: false, error: "Uno de los jugadores tiene otro partido previsto en ese horario" }, 409, origin);

    const before = { date: m.date, time: m.time, court: m.court };

    m.history = Array.isArray(m.history) ? m.history : [];

    m.history.push({ type: "rescheduled", by: user.id, at: now(), proposalId: p.id, from: before, to: { date: p.date, time: p.time, court: p.court }, reason: p.reason, externalCourtConfirmed: true });

    m.date = p.date;

    m.time = p.time;

    m.court = p.court;

    m.status = "rescheduled";

    await put(env, "matches", matches);

    p.status = "accepted";

    p.resolvedAt = now();

    p.resolvedBy = user.id;

    p.externalCourtConfirmed = true;

    p.events.push({ type: "accepted", by: user.id, at: now(), externalCourtConfirmed: true });

    await put(env, "proposals", proposals);

    return response({ ok: true, proposal: p, match: m }, 200, origin);

  }

  // Resultados V1.2: los antiguos siguen siendo definitivos.
  if (path === "/api/results" && req.method === "POST") {
    const matchId = str(body.matchId, 80), sets = body.sets;
    if (!scoreIsValid({ sets })) return response({ok:false,error:"Introduce exactamente dos sets válidos"},400,origin);
    const matches = await read(env,"matches",[]), m=matches.find(x=>x.id===matchId);
    if (!m) return response({ok:false,error:"Partido inexistente"},404,origin);
    const involved = !!user.playerId && [m.playerAId,m.playerBId].includes(user.playerId);
    if (!allowAdmin(user) && !involved) return response({ok:false,error:"No participas en este partido"},403,origin);
    if (m.result) return response({ok:false,error:"Resultado ya confirmado; solicita revisión a administración"},409,origin);
    if (m.pendingResult) return response({ok:false,error:"Ya hay un resultado pendiente de confirmación"},409,origin);
    if (allowAdmin(user) && !involved) {
      // El administrador puede seguir introduciendo resultados definitivos (compatibilidad V0.3).
      const pa=Number(sets[0][0]>sets[0][1])+Number(sets[1][0]>sets[1][1]);
      m.result={sets,pointsA:pa,pointsB:2-pa,updatedAt:now(),updatedBy:user.id,confirmedAt:now(),source:"admin"};
      m.status="played";
    } else {
      m.pendingResult={sets,submittedBy:user.id,submittedPlayerId:user.playerId,submittedAt:now(),status:"pending",history:[{action:"submitted",by:user.id,at:now()}]};
      m.status="result_pending";
    }
    await put(env,"matches",matches);
    return response({ok:true,match:m},200,origin);
  }
  if (path === "/api/results/respond" && req.method === "POST") {
    const matchId=str(body.matchId,80),action=str(body.action,24);
    if (!["confirm","dispute"].includes(action)) return response({ok:false,error:"Acción incorrecta"},400,origin);
    const matches=await read(env,"matches",[]),m=matches.find(x=>x.id===matchId);
    if (!m) return response({ok:false,error:"Partido no encontrado"},404,origin);
    const p=m.pendingResult;
    if (!p || p.status!=="pending" || m.result) return response({ok:false,error:"No hay resultado pendiente"},409,origin);
    if (!allowAdmin(user) && (!user.playerId || ![m.playerAId,m.playerBId].includes(user.playerId))) return response({ok:false,error:"No participas en el partido"},403,origin);
    if (p.submittedBy===user.id) return response({ok:false,error:"No puedes confirmar tu propio resultado"},403,origin);
    p.history=Array.isArray(p.history)?p.history:[];
    p.history.push({action,by:user.id,at:now()});
    if (action==="dispute") {
      const reason=str(body.reason,300);
      if (reason.length<3) return response({ok:false,error:"Indica el motivo de la discrepancia"},400,origin);
      p.status="disputed";p.reason=reason;p.respondedAt=now();m.status="result_disputed";
    } else {
      const sets=p.sets,pa=Number(sets[0][0]>sets[0][1])+Number(sets[1][0]>sets[1][1]);
      m.result={sets,pointsA:pa,pointsB:2-pa,updatedAt:now(),updatedBy:p.submittedBy,confirmedBy:user.id,confirmedAt:now(),source:"players"};
      m.status="played";p.status="confirmed";p.respondedAt=now();
    }
    await put(env,"matches",matches);
    return response({ok:true,match:m},200,origin);
  }
  if (path === "/api/results/reopen" && req.method === "POST") {
    if (!allowAdmin(user)) return response({ok:false,error:"Solo administración"},403,origin);
    const matchId=str(body.matchId,80),matches=await read(env,"matches",[]),m=matches.find(x=>x.id===matchId);
    if (!m) return response({ok:false,error:"Partido inexistente"},404,origin);
    if (m.result) return response({ok:false,error:"Los resultados confirmados no se reabren desde esta opción"},409,origin);
    if (!m.pendingResult || m.pendingResult.status!=="disputed") return response({ok:false,error:"No hay discrepancia pendiente"},409,origin);
    m.resultReviewHistory=Array.isArray(m.resultReviewHistory)?m.resultReviewHistory:[];
    m.resultReviewHistory.push({...m.pendingResult,clearedAt:now(),clearedBy:user.id});
    m.pendingResult=null;m.status="scheduled";
    await put(env,"matches",matches);
    return response({ok:true,match:m},200,origin);
  }
  return response({ ok: false, error: "Ruta no disponible" }, 404, origin);

}

__name(handler, "handler");

var worker_default = { async fetch(req, env) {

  try {

    return await handler(req, env);

  } catch (e) {

    console.error("LDM API error", e);

    return response({ ok: false, error: "Error interno" }, 500, req.headers.get("Origin") || "");

  }

} };

export {

  worker_default as default

};


