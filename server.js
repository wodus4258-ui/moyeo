// ============================================================
// moyeo signaling server
// - Supabase JWT 검증
// - 방(room) 인메모리 관리
// - WebRTC offer/answer/ICE 중계
// - 채팅 릴레이
// - 친구 presence 브로드캐스트
// ============================================================

const http = require('http');
const { WebSocketServer } = require('ws');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const https = require('https');

// JWKS 캐시 (ES256/RS256 검증용)
let _jwksCache = { keys: null, fetchedAt: 0 };
async function fetchJWKS(force){
  if(!force && _jwksCache.keys && Date.now() - _jwksCache.fetchedAt < 3600000){
    return _jwksCache.keys;
  }
  const url = SUPABASE_URL.replace(/\/$/, '') + '/auth/v1/.well-known/jwks.json';
  try{
    const res = await fetch(url);
    if(!res.ok) return null;
    const data = await res.json();
    _jwksCache = { keys: data.keys || [], fetchedAt: Date.now() };
    return _jwksCache.keys;
  }catch(e){
    console.error('[JWKS] fetch failed:', e.message);
    return null;
  }
}
function base64UrlDecode(str){
  str = String(str).replace(/-/g, '+').replace(/_/g, '/');
  while(str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

async function verifySupabaseJWT(token){
  try{
    if(!token) return null;
    const parts = token.split('.');
    if(parts.length !== 3) return null;
    const headerB64 = parts[0], payloadB64 = parts[1], signatureB64 = parts[2];
    let header, payload;
    try{
      header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'));
      payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
    }catch(e){ return null; }
    if(payload.exp && (payload.exp * 1000) < Date.now()) return null;

    const signatureInput = headerB64 + '.' + payloadB64;
    const signature = base64UrlDecode(signatureB64);

    if(header.alg === 'HS256'){
      const expected = crypto.createHmac('sha256', SUPABASE_JWT_SECRET).update(signatureInput).digest();
      if(expected.length !== signature.length) return null;
      if(!crypto.timingSafeEqual(expected, signature)) return null;
      return payload;
    }

    if(header.alg === 'ES256' || header.alg === 'RS256'){
      let keys = await fetchJWKS(false);
      let jwk = (keys || []).find(k => k.kid === header.kid);
      if(!jwk){
        keys = await fetchJWKS(true);
        jwk = (keys || []).find(k => k.kid === header.kid);
      }
      if(!jwk) return null;
      const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
      const data = Buffer.from(signatureInput, 'utf8');
      let ok = false;
      if(header.alg === 'ES256'){
        ok = crypto.verify('sha256', data, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature);
      } else {
        ok = crypto.verify('sha256', data, publicKey, signature);
      }
      if(!ok) return null;
      return payload;
    }

    return null;
  }catch(e){
    console.error('[JWT] verify error:', e.message);
    return null;
  }
}

// ---------- 환경변수 ----------
const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  SUPABASE_JWT_SECRET,
  ALLOWED_ORIGIN = '*',
  PORT = 10000,
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('[FATAL] 필수 환경변수 누락: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY');
  process.exit(1);
}
// SUPABASE_JWT_SECRET 은 HS256 검증 시에만 필요 (새 프로젝트는 ES256 이라 없어도 됨)

// ---------- Supabase (service_role, 서버 전용) ----------
// 디버그: 어떤 키를 쓰고 있는지 앞 20자만 출력 (전체 노출 X)
console.log('[boot] SUPABASE_URL =', SUPABASE_URL);
console.log('[boot] SERVICE_ROLE_KEY prefix =', (SUPABASE_SERVICE_ROLE_KEY || '').slice(0, 20) + '...');

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

// ---------- 상태 ----------
// clients: clientId -> client 객체
// rooms: roomCode -> { code, roomId, hostId, hostType, onAir, layout, quality, members:Map<clientId, memberInfo>, hasPin, pinHash }
// userToClients: userId(uuid) -> Set<clientId>  (한 회원이 여러 탭 열 수 있음)
const clients = new Map();
const rooms = new Map();
const userToClients = new Map();

let nextClientId = 1;

// ============================================================
// HTTP 서버 (Render health check)
// ============================================================
const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    });
    res.end(JSON.stringify({
      ok: true,
      clients: clients.size,
      rooms: rooms.size,
      uptime: process.uptime(),
    }));
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('moyeo signaling server');
});

// ============================================================
// WebSocket
// ============================================================
const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
  const clientId = 'c' + (nextClientId++);
  const client = {
    id: clientId,
    ws,
    userId: null,
    accountId: null,
    nickname: null,
    roomCode: null,
    isAlive: true,
  };
  clients.set(clientId, client);

  console.log(`[+] client ${clientId} connected (total: ${clients.size})`);

  // ---------- ping/pong ----------
  ws.on('pong', () => { client.isAlive = true; });

  // ---------- 메시지 처리 ----------
  ws.on('message', async (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }
    if (!msg || typeof msg.type !== 'string') return;

    try {
      await handleMessage(client, msg);
    } catch (err) {
      console.error(`[!] ${clientId} handler error:`, err.message);
    }
  });

  // ---------- 연결 종료 ----------
  ws.on('close', () => {
    console.log(`[-] client ${clientId} disconnected`);
    leaveRoom(client);
    if (client.userId) {
      const set = userToClients.get(client.userId);
      if (set) {
        set.delete(clientId);
        if (set.size === 0) {
          userToClients.delete(client.userId);
          broadcastPresence(client.userId, false);
        }
      }
    }
    clients.delete(clientId);
  });

  ws.on('error', () => {});
});

// ============================================================
// 메시지 라우터
// ============================================================
async function handleMessage(client, msg) {
  // 인증 전에는 auth / ping 만 허용
  if (!client.userId && msg.type !== 'auth' && msg.type !== 'ping') {
    return send(client, { type: 'auth:error', message: 'not authenticated' });
  }

  switch (msg.type) {
    case 'auth':            return handleAuth(client, msg);
    case 'ping':            return send(client, { type: 'pong' });
    case 'room:join':       return handleRoomJoin(client, msg);
    case 'room:leave':      return leaveRoom(client);
    case 'rtc:offer':       return relayToRoom(client, msg.to, { type: 'rtc:offer', from: client.id, sdp: msg.sdp });
    case 'rtc:answer':      return relayToRoom(client, msg.to, { type: 'rtc:answer', from: client.id, sdp: msg.sdp });
    case 'rtc:ice':         return relayToRoom(client, msg.to, { type: 'rtc:ice', from: client.id, candidate: msg.candidate });
    case 'chat:send':       return handleChatSend(client, msg);
    case 'broadcast:state': return handleBroadcastState(client, msg);
    case 'query-presence':  return handleQueryPresence(client, msg);
    case 'notify-member':   return handleNotifyMember(client, msg);
    case 'file:relay':      return handleFileRelay(client, msg);
    case 'file:broadcast':  return handleFileBroadcast(client, msg);
    case 'room:delete':     return handleRoomDelete(client);
  }
}

// ============================================================
// 파일 호스팅 릴레이
// ============================================================
function handleFileRelay(client, msg) {
  if (!client.roomCode) return;
  if (!msg.to) return;
  const target = clients.get(msg.to);
  if (!target || target.roomCode !== client.roomCode) return;
  send(target, {
    type: 'file:relay',
    from: client.id,
    fromNickname: client.nickname,
    kind: msg.kind,
    payload: msg.payload,
  });
}

function handleFileBroadcast(client, msg) {
  if (!client.roomCode) return;
  broadcastToRoom(client.roomCode, {
    type: 'file:broadcast',
    from: client.id,
    fromNickname: client.nickname,
    kind: msg.kind,
    payload: msg.payload,
  }, client.id);
}

// ============================================================
// 인증
// ============================================================
async function handleAuth(client, msg) {
  const token = msg.jwt;
  if (!token) return send(client, { type: 'auth:error', message: 'no token' });

  const payload = await verifySupabaseJWT(token);
  if (!payload) {
    return send(client, { type: 'auth:error', message: 'invalid token' });
  }

  const userId = payload.sub;
  if (!userId) return send(client, { type: 'auth:error', message: 'no sub' });

  // 프로필 조회
  console.log(`[auth] looking up profile for userId=${userId}`);
  const { data: profile, error } = await supabase
    .from('profiles')
    .select('account_id, nickname')
    .eq('id', userId)
    .single();

  if (error || !profile) {
    console.error(`[auth] profile lookup FAILED for ${userId}`);
    console.error(`[auth] error:`, JSON.stringify(error, null, 2));
    console.error(`[auth] data:`, profile);
    return send(client, { type: 'auth:error', message: 'profile not found' });
  }
  console.log(`[auth] profile OK: ${profile.account_id} / ${profile.nickname}`);

  client.userId = userId;
  client.accountId = profile.account_id;
  client.nickname = profile.nickname;

  // presence 등록
  let set = userToClients.get(userId);
  const isNew = !set;
  if (!set) { set = new Set(); userToClients.set(userId, set); }
  set.add(client.id);

  // 온라인 브로드캐스트 (새로 접속한 경우만)
  if (isNew) broadcastPresence(userId, true);

  send(client, {
    type: 'auth:ok',
    userId,
    accountId: profile.account_id,
    nickname: profile.nickname,
  });

  console.log(`[auth] ${client.id} as ${profile.nickname} (${userId.slice(0, 8)})`);
}

// ============================================================
// 방 입장
// ============================================================
async function handleRoomJoin(client, msg) {
  const { code, pin } = msg;
  if (!code || typeof code !== 'string') {
    return send(client, { type: 'room:error', message: 'invalid code' });
  }

  // 이전 방 퇴장
  if (client.roomCode) leaveRoom(client);

  // 방 조회
  const { data: room, error } = await supabase
    .from('rooms')
    .select('id, code, host_id, title, host_type, visibility, has_pin, max_participants, on_air')
    .eq('code', code)
    .single();

  if (error || !room) {
    return send(client, { type: 'room:error', message: 'room not found' });
  }

  // PIN 검증 (파일 방)
  if (room.has_pin) {
    const { data: secret } = await supabase
      .from('room_secrets')
      .select('pin_hash')
      .eq('room_id', room.id)
      .single();

    if (!secret || !pin || secret.pin_hash !== hashPin(pin)) {
      return send(client, { type: 'room:error', message: 'wrong pin' });
    }
  }

  // 권한 검증
  if (room.visibility === 'private') {
    // 초대받은 사람인지 확인
    const { data: member } = await supabase
      .from('room_members')
      .select('user_id')
      .eq('room_id', room.id)
      .eq('user_id', client.userId)
      .maybeSingle();

    if (!member && room.host_id !== client.userId) {
      return send(client, { type: 'room:error', message: 'not invited' });
    }
  }
  // public / friends 는 클라이언트 RLS 에서 이미 필터링됨 (조회했다는 것 자체가 권한 있음)

  // 인메모리 방 생성 또는 가져오기
  let memRoom = rooms.get(code);
  if (!memRoom) {
    memRoom = {
      code: room.code,
      roomId: room.id,
      hostId: room.host_id,
      hostType: room.host_type,
      title: room.title,
      hasPin: room.has_pin,
      maxParticipants: room.max_participants,
      onAir: room.on_air,
      layout: 'split',
      quality: 'mid',
      members: new Map(),
    };
    rooms.set(code, memRoom);
  }

  // 정원 초과 검사
  if (memRoom.members.size >= memRoom.maxParticipants) {
    return send(client, { type: 'room:error', message: 'room full' });
  }

  // 같은 회원의 다른 탭이 이미 있으면 그건 나가게 함 (한 사람 = 한 탭 in room)
  for (const [cid, m] of memRoom.members) {
    if (m.userId === client.userId && cid !== client.id) {
      const oldClient = clients.get(cid);
      if (oldClient) {
        send(oldClient, { type: 'room:error', message: 'duplicate session' });
        leaveRoom(oldClient);
      }
    }
  }

  // 방 멤버로 등록
  const memberInfo = {
    id: client.id,
    userId: client.userId,
    nickname: client.nickname,
    isHost: room.host_id === client.userId,
  };
  memRoom.members.set(client.id, memberInfo);
  client.roomCode = code;

  // 클라이언트에게 입장 완료 알림 (자기 제외한 기존 멤버 목록)
  const otherMembers = [];
  for (const [cid, m] of memRoom.members) {
    if (cid !== client.id) otherMembers.push(m);
  }

  send(client, {
    type: 'room:joined',
    code: memRoom.code,
    roomId: memRoom.roomId,
    hostId: memRoom.hostId,
    hostType: memRoom.hostType,
    title: memRoom.title,
    isHost: memberInfo.isHost,
    members: otherMembers,
    broadcast: {
      onAir: memRoom.onAir,
      layout: memRoom.layout,
      quality: memRoom.quality,
    },
  });

  // 기존 멤버들에게 새 멤버 알림
  broadcastToRoom(code, {
    type: 'room:member-joined',
    member: memberInfo,
  }, client.id);

  // DB participant_count 갱신
  await supabase
    .from('rooms')
    .update({ participant_count: memRoom.members.size })
    .eq('id', memRoom.roomId);

  console.log(`[room] ${client.nickname} joined ${code} (${memRoom.members.size}/${memRoom.maxParticipants})`);
}

// ============================================================
// 방 퇴장
// ============================================================
function leaveRoom(client) {
  if (!client.roomCode) return;
  const code = client.roomCode;
  const memRoom = rooms.get(code);
  client.roomCode = null;
  if (!memRoom) return;

  memRoom.members.delete(client.id);

  broadcastToRoom(code, {
    type: 'room:member-left',
    memberId: client.id,
  });

  // 방이 비었으면 메모리에서 제거 + DB 상태 초기화
  if (memRoom.members.size === 0) {
    rooms.delete(code);
    supabase
      .from('rooms')
      .update({ on_air: false, participant_count: 0 })
      .eq('id', memRoom.roomId)
      .then(() => {});
    console.log(`[room] ${code} closed (empty)`);
  } else {
    // 남은 인원 수 갱신
    supabase
      .from('rooms')
      .update({ participant_count: memRoom.members.size })
      .eq('id', memRoom.roomId)
      .then(() => {});
  }
}

// ============================================================
// 방 삭제 (호스트 전용, DB row까지 완전 삭제)
//  - 서버가 service_role 로 DB delete (RLS 우회)
//  - room_secrets / room_members 는 ON DELETE CASCADE 로 자동 정리
//  - 모든 멤버에게 room:deleted 브로드캐스트 후 인메모리 정리
// ============================================================
async function handleRoomDelete(client) {
  if (!client.roomCode) return;
  const memRoom = rooms.get(client.roomCode);
  if (!memRoom) return;
  if (memRoom.hostId !== client.userId) {
    return send(client, { type: 'room:error', message: 'only host can delete' });
  }

  const code = memRoom.code;
  const roomId = memRoom.roomId;

  // 1) DB row 삭제 (실패 시 아무도 내보내지 않음)
  const { error } = await supabase.from('rooms').delete().eq('id', roomId);
  if (error) {
    console.error('[room:delete] DB error:', error.message);
    return send(client, { type: 'room:error', message: 'delete failed' });
  }

  // 2) 모든 멤버(호스트 포함)에게 브로드캐스트
  broadcastToRoom(code, { type: 'room:deleted', roomId });

  // 3) 인메모리 정리
  for (const [cid] of memRoom.members) {
    const c = clients.get(cid);
    if (c) c.roomCode = null;
  }
  rooms.delete(code);

  console.log(`[room] ${code} DELETED by ${client.nickname}`);
}

// ============================================================
// 채팅 릴레이
// ============================================================
function handleChatSend(client, msg) {
  if (!client.roomCode) return;
  const text = String(msg.text || '').slice(0, 2000);
  if (!text.trim()) return;

  const ts = Date.now();

  // sender 제외한 나머지에게만 broadcast
  broadcastToRoom(client.roomCode, {
    type: 'chat:message',
    from: client.id,
    fromNickname: client.nickname,
    fromUserId: client.userId,
    text,
    ts,
  }, client.id);

  // sender 본인에게만 self:true 로 별도 전송
  send(client, {
    type: 'chat:message',
    from: client.id,
    fromNickname: client.nickname,
    fromUserId: client.userId,
    text,
    ts,
    self: true,
  });
}

// ============================================================
// 방송 상태 (호스트만)
// ============================================================
async function handleBroadcastState(client, msg) {
  if (!client.roomCode) return;
  const memRoom = rooms.get(client.roomCode);
  if (!memRoom) return;
  if (memRoom.hostId !== client.userId) return; // 호스트만

  if (typeof msg.onAir === 'boolean') memRoom.onAir = msg.onAir;
  if (typeof msg.layout === 'string') memRoom.layout = msg.layout;
  if (typeof msg.quality === 'string') memRoom.quality = msg.quality;

  // DB on_air 갱신
  if (typeof msg.onAir === 'boolean') {
    await supabase
      .from('rooms')
      .update({ on_air: msg.onAir })
      .eq('id', memRoom.roomId);
  }

  broadcastToRoom(client.roomCode, {
    type: 'broadcast:state',
    onAir: memRoom.onAir,
    layout: memRoom.layout,
    quality: memRoom.quality,
  });
}

// ============================================================
// 유틸리티
// ============================================================
function send(client, obj) {
  try { client.ws.send(JSON.stringify(obj)); } catch (e) {}
}

function relayToRoom(fromClient, toClientId, payload) {
  if (!fromClient.roomCode) return;
  const toClient = clients.get(toClientId);
  if (!toClient || toClient.roomCode !== fromClient.roomCode) return;
  send(toClient, payload);
}

function broadcastToRoom(code, obj, exceptId) {
  const memRoom = rooms.get(code);
  if (!memRoom) return;
  const json = JSON.stringify(obj);
  for (const [cid, m] of memRoom.members) {
    if (cid === exceptId) continue;
    const c = clients.get(cid);
    if (c) { try { c.ws.send(json); } catch (e) {} }
  }
}

// 프론트가 친구들 presence를 일괄 조회
function handleQueryPresence(client, msg) {
  const ids = Array.isArray(msg.userIds) ? msg.userIds : [];
  const online = {};
  ids.forEach(uid => {
    const set = userToClients.get(uid);
    online[uid] = !!(set && set.size > 0);
  });
  send(client, { type: 'presence:query-result', online });
}

// 친구 요청/수락 등 상대에게 즉시 알림
function handleNotifyMember(client, msg) {
  const targetId = msg.targetUserId;
  if (!targetId || typeof targetId !== 'string') return;
  const set = userToClients.get(targetId);
  if (!set) return;
  set.forEach(cid => {
    const c = clients.get(cid);
    if (c) send(c, { type: 'friend:update' });
  });
}

function broadcastPresence(userId, online) {
  // 이 유저와 친구인 모든 접속자에게 알림
  // (지금은 단순히 모든 접속자에게 broadcast — 클라이언트가 친구 여부 판단)
  const msg = JSON.stringify({ type: 'presence:update', userId, online });
  for (const c of clients.values()) {
    if (c.userId && c.ws.readyState === 1) {
      try { c.ws.send(msg); } catch (e) {}
    }
  }
}

// PIN hash (SHA-256)
function hashPin(pin) {
  return crypto.createHash('sha256').update(String(pin)).digest('hex');
}

// ============================================================
// 하트비트 (죽은 연결 감지)
// ============================================================
setInterval(() => {
  for (const [cid, client] of clients) {
    if (!client.isAlive) {
      try { client.ws.terminate(); } catch (e) {}
      clients.delete(cid);
      continue;
    }
    client.isAlive = false;
    try { client.ws.ping(); } catch (e) {}
  }
}, 30000);

// ============================================================
// 시작
// ============================================================
server.listen(PORT, () => {
  console.log(`moyeo signaling server listening on :${PORT}`);
  console.log(`  Supabase: ${SUPABASE_URL}`);
  console.log(`  CORS origin: ${ALLOWED_ORIGIN}`);
});