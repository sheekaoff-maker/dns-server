import * as dgram from 'dgram';
import { BackendClient, PolicyResult } from './backend-client';

const UPSTREAM_DNS_LIST = (process.env.UPSTREAM_DNS || '1.1.1.1,8.8.8.8')
  .split(',')
  .map((s) => s.trim());

const UPSTREAM_TIMEOUT = 1500;

// --- DNS auto-pairing probe detection ---
//
// A device's normal OS resolver can't carry an app-level token — DNS has no
// field for that. Pairing instead works by the parent's phone sending one
// raw UDP query, directly at this resolver's IP, for the hostname
// `<token>.pair.guardtime.local`. We pattern-match that hostname here (must
// match backend's PAIR_DOMAIN_SUFFIX exactly), confirm it against the
// backend, and answer with a synthetic A record so the probe socket gets a
// reply and knows the probe reached us — the actual IP in that record is
// never used for anything.
const PAIR_DOMAIN_SUFFIX = process.env.PAIR_DOMAIN_SUFFIX || 'pair.guardtime.local';
const RESOLVER_REGION = process.env.RESOLVER_REGION || undefined;
const PAIR_PROBE_ACK_IP = '127.0.0.1';

const PAIR_HOSTNAME_PATTERN = new RegExp(
  `^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\.${PAIR_DOMAIN_SUFFIX.replace(/\./g, '\\.')}$`,
  'i',
);

function extractPairToken(domain: string): string | null {
  const lower = domain.toLowerCase().replace(/\.$/, '');
  const match = PAIR_HOSTNAME_PATTERN.exec(lower);
  return match ? match[1] : null;
}

// DNS record type numbers
const TYPE_A = 1;
const TYPE_AAAA = 28;

// DNS response flags
const FLAGS_RESPONSE = 0x8000;
const FLAGS_RECURSION_AVAILABLE = 0x0100;
const FLAGS_RECURSION_DESIRED = 0x0100;
const RCODE_SERVFAIL = 0x0002;
const RCODE_NOERROR = 0x0000;

function pickUpstream(): string {
  return UPSTREAM_DNS_LIST[Math.floor(Math.random() * UPSTREAM_DNS_LIST.length)];
}

/**
 * Parse domain name from DNS packet starting at offset.
 * Returns { name: string, endOffset: number }
 */
const MAX_COMPRESSION_JUMPS = 128;

function parseName(buf: Buffer, offset: number): { name: string; endOffset: number } {
  const labels: string[] = [];
  let pos = offset;
  let jumped = false;
  let jumpPos = -1;
  let jumps = 0;

  while (pos < buf.length) {
    const len = buf[pos];
    if (len === 0) {
      pos++;
      break;
    }
    // DNS compression pointer
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) {
        throw new Error('malformed DNS packet: truncated compression pointer');
      }
      if (++jumps > MAX_COMPRESSION_JUMPS) {
        throw new Error('malformed DNS packet: compression pointer loop detected');
      }
      if (!jumped) jumpPos = pos + 2;
      const ptr = ((len & 0x3f) << 8) | buf[pos + 1];
      if (ptr >= buf.length) {
        throw new Error('malformed DNS packet: compression pointer out of bounds');
      }
      pos = ptr;
      jumped = true;
      continue;
    }
    pos++;
    labels.push(buf.toString('ascii', pos, pos + len));
    pos += len;
  }

  return { name: labels.join('.'), endOffset: jumped ? jumpPos : pos };
}

export interface DnsQuery {
  id: number;
  flags: number;
  domain: string;
  qtype: number;
  qclass: number;
  questionEndOffset: number;
}

/**
 * Parse a DNS query packet to extract domain and query type.
 */
export function parseQuery(buf: Buffer): DnsQuery {
  const id = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  const qdcount = buf.readUInt16BE(4);

  // Skip header (12 bytes), parse first question
  let offset = 12;
  const { name, endOffset } = parseName(buf, offset);
  const qtype = buf.readUInt16BE(endOffset);
  const qclass = buf.readUInt16BE(endOffset + 2);

  return {
    id,
    flags,
    domain: name,
    qtype,
    qclass,
    questionEndOffset: endOffset + 4,
  };
}

/**
 * Build a DNS response buffer for a BLOCK result.
 * Returns A record 0.0.0.0 or AAAA record ::
 */
export function buildBlockResponse(query: DnsQuery): Buffer {
  const domain = query.domain;
  const qtype = query.qtype;

  // Encode domain name
  const nameParts = domain.split('.');
  const nameBuf = Buffer.alloc(domain.length + 2);
  let off = 0;
  for (const part of nameParts) {
    nameBuf[off++] = part.length;
    nameBuf.write(part, off, 'ascii');
    off += part.length;
  }
  nameBuf[off++] = 0;

  // Answer section: name pointer (compression to question), type, class, ttl, rdlength, rdata
  const answerSize = 2 + 2 + 2 + 4 + 2 + (qtype === TYPE_AAAA ? 16 : 4);
  const headerSize = 12;

  const buf = Buffer.alloc(headerSize + nameBuf.length + 4 + answerSize);
  let pos = 0;

  // Header
  buf.writeUInt16BE(query.id, pos); pos += 2;
  buf.writeUInt16BE(FLAGS_RESPONSE | FLAGS_RECURSION_AVAILABLE | RCODE_NOERROR, pos); pos += 2;
  buf.writeUInt16BE(1, pos); pos += 2;  // QDCOUNT
  buf.writeUInt16BE(1, pos); pos += 2;  // ANCOUNT
  buf.writeUInt16BE(0, pos); pos += 2;  // NSCOUNT
  buf.writeUInt16BE(0, pos); pos += 2;  // ARCOUNT

  // Question section
  nameBuf.copy(buf, pos); pos += nameBuf.length;
  buf.writeUInt16BE(qtype, pos); pos += 2;
  buf.writeUInt16BE(query.qclass, pos); pos += 2;

  // Answer section — name pointer to offset 12 (question name)
  buf.writeUInt16BE(0xc00c, pos); pos += 2;
  buf.writeUInt16BE(qtype, pos); pos += 2;
  buf.writeUInt16BE(query.qclass, pos); pos += 2;
  buf.writeUInt32BE(30, pos); pos += 4;  // TTL

  if (qtype === TYPE_AAAA) {
    buf.writeUInt16BE(16, pos); pos += 2;  // rdlength
    // :: = 16 zero bytes
    for (let i = 0; i < 16; i++) { buf[pos++] = 0; }
  } else {
    buf.writeUInt16BE(4, pos); pos += 2;  // rdlength
    // 0.0.0.0
    buf.writeUInt32BE(0, pos); pos += 4;
  }

  return buf.slice(0, pos);
}

/**
 * Build a synthetic ack response for a resolved pairing/beacon probe query
 * — the probe sender only needs a reply to arrive, never resolves the IP.
 */
export function buildProbeAckResponse(query: DnsQuery): Buffer {
  const domain = query.domain;
  const qtype = query.qtype;

  const nameParts = domain.split('.');
  const nameBuf = Buffer.alloc(domain.length + 2);
  let off = 0;
  for (const part of nameParts) {
    nameBuf[off++] = part.length;
    nameBuf.write(part, off, 'ascii');
    off += part.length;
  }
  nameBuf[off++] = 0;

  const answerSize = 2 + 2 + 2 + 4 + 2 + (qtype === TYPE_AAAA ? 16 : 4);
  const headerSize = 12;

  const buf = Buffer.alloc(headerSize + nameBuf.length + 4 + answerSize);
  let pos = 0;

  buf.writeUInt16BE(query.id, pos); pos += 2;
  buf.writeUInt16BE(FLAGS_RESPONSE | FLAGS_RECURSION_AVAILABLE | RCODE_NOERROR, pos); pos += 2;
  buf.writeUInt16BE(1, pos); pos += 2;
  buf.writeUInt16BE(1, pos); pos += 2;
  buf.writeUInt16BE(0, pos); pos += 2;
  buf.writeUInt16BE(0, pos); pos += 2;

  nameBuf.copy(buf, pos); pos += nameBuf.length;
  buf.writeUInt16BE(qtype, pos); pos += 2;
  buf.writeUInt16BE(query.qclass, pos); pos += 2;

  buf.writeUInt16BE(0xc00c, pos); pos += 2;
  buf.writeUInt16BE(qtype, pos); pos += 2;
  buf.writeUInt16BE(query.qclass, pos); pos += 2;
  buf.writeUInt32BE(5, pos); pos += 4; // short TTL — this record is never meant to be cached

  if (qtype === TYPE_AAAA) {
    buf.writeUInt16BE(16, pos); pos += 2;
    for (let i = 0; i < 15; i++) { buf[pos++] = 0; }
    buf[pos++] = 1; // ::1
  } else {
    buf.writeUInt16BE(4, pos); pos += 2;
    const parts = PAIR_PROBE_ACK_IP.split('.').map(Number);
    for (const p of parts) buf[pos++] = p;
  }

  return buf.slice(0, pos);
}

/**
 * Build a SERVFAIL DNS response.
 */
export function buildServfailResponse(query: DnsQuery): Buffer {
  const buf = Buffer.alloc(12);
  buf.writeUInt16BE(query.id, 0);
  buf.writeUInt16BE(FLAGS_RESPONSE | FLAGS_RECURSION_AVAILABLE | RCODE_SERVFAIL, 2);
  buf.writeUInt16BE(0, 6);  // ANCOUNT
  buf.writeUInt16BE(0, 8);  // NSCOUNT
  buf.writeUInt16BE(0, 10); // ARCOUNT
  return buf;
}

/**
 * Forward raw DNS query to upstream and return the response buffer.
 * Timeout after UPSTREAM_TIMEOUT ms.
 */
export function forwardToUpstream(rawQuery: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const upstream = pickUpstream();
    const socket = dgram.createSocket('udp4');
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        socket.close();
        reject(new Error(`upstream timeout (${upstream})`));
      }
    }, UPSTREAM_TIMEOUT);

    socket.on('message', (msg) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        socket.close();
        resolve(msg);
      }
    });

    socket.on('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        socket.close();
        reject(err);
      }
    });

    socket.send(rawQuery, 53, upstream);
  });
}

/**
 * Main resolve function: check policy, block or forward.
 */
export async function resolve(
  rawQuery: Buffer,
  sourceIp: string,
  backendClient: BackendClient,
): Promise<Buffer> {
  const query = parseQuery(rawQuery);

  const pairToken = extractPairToken(query.domain);
  if (pairToken) {
    const confirmed = await backendClient.confirmPair(pairToken, sourceIp, RESOLVER_REGION);
    console.info(`[PAIR PROBE] token=${pairToken.slice(0, 8)}… sourceIp=${sourceIp} confirmed=${confirmed}`);
    return buildProbeAckResponse(query);
  }

  const policy = await backendClient.checkPolicy(sourceIp, query.domain);

  if (policy.action === 'BLOCK') {
    console.info(`[BLOCK] domain=${query.domain} sourceIp=${sourceIp} reason=${policy.reason || 'unknown'}`);
    return buildBlockResponse(query);
  }

  // ALLOW: forward to upstream
  try {
    const upstreamResponse = await forwardToUpstream(rawQuery);
    console.debug(`[ALLOW] domain=${query.domain} sourceIp=${sourceIp}`);
    return upstreamResponse;
  } catch (err: any) {
    console.warn(`[FORWARD FAILED] domain=${query.domain}: ${err.message}`);
    return buildServfailResponse(query);
  }
}
