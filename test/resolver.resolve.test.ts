import { EventEmitter } from 'events';

jest.mock('dgram', () => ({
  createSocket: jest.fn(),
}));

import * as dgram from 'dgram';
import { resolve, parseQuery } from '../src/resolver';
import { BackendClient, PolicyResult } from '../src/backend-client';
import { encodeDnsQuery } from './helpers/dns-packet';

function makeFakeSocket() {
  const sock: any = new EventEmitter();
  sock.send = jest.fn();
  sock.close = jest.fn();
  return sock;
}

function fakeBackendClient(
  result: PolicyResult | ((domain: string) => PolicyResult),
  confirmPairResult = true,
): BackendClient {
  return {
    checkPolicy: jest.fn(async (_sourceIp: string, domain: string) =>
      typeof result === 'function' ? result(domain) : result,
    ),
    confirmPair: jest.fn(async () => confirmPairResult),
  } as unknown as BackendClient;
}

describe('resolve', () => {
  let sockets: any[];

  beforeEach(() => {
    sockets = [];
    (dgram.createSocket as jest.Mock).mockImplementation(() => {
      const s = makeFakeSocket();
      sockets.push(s);
      return s;
    });
    jest.spyOn(console, 'info').mockImplementation(() => {});
    jest.spyOn(console, 'debug').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.useRealTimers();
  });

  it('returns a BLOCK response when policy says BLOCK', async () => {
    const query = encodeDnsQuery(11, 'blocked.example');
    const backend = fakeBackendClient({ action: 'BLOCK', reason: 'schedule' });

    const responsePromise = resolve(query, '10.0.0.5', backend);
    const response = await responsePromise;

    expect(response.readUInt16BE(0)).toBe(11);
    // 0.0.0.0 rdata for a BLOCK A response
    expect(response.subarray(response.length - 4).equals(Buffer.from([0, 0, 0, 0]))).toBe(true);
    // BLOCK never touches upstream — no socket should be created
    expect(dgram.createSocket).not.toHaveBeenCalled();
  });

  it('forwards to upstream and returns its response when policy says ALLOW', async () => {
    const query = encodeDnsQuery(22, 'allowed.example');
    const backend = fakeBackendClient({ action: 'ALLOW' });

    const responsePromise = resolve(query, '10.0.0.5', backend);
    // let the socket get created, then simulate the upstream reply
    await Promise.resolve();
    await Promise.resolve();
    const upstreamResponse = Buffer.from([9, 9, 9, 9]);
    sockets[0].emit('message', upstreamResponse);

    const response = await responsePromise;
    expect(response).toEqual(upstreamResponse);
  });

  it('returns SERVFAIL when policy is ALLOW but upstream forwarding fails', async () => {
    const query = encodeDnsQuery(33, 'flaky.example');
    const backend = fakeBackendClient({ action: 'ALLOW' });

    const responsePromise = resolve(query, '10.0.0.5', backend);
    await Promise.resolve();
    await Promise.resolve();
    sockets[0].emit('error', new Error('ENETUNREACH'));

    const response = await responsePromise;
    expect(response.length).toBe(12);
    expect(response.readUInt16BE(0)).toBe(33);
    expect(response.readUInt16BE(2) & 0x000f).toBe(0x0002); // SERVFAIL
  });

  it('returns SERVFAIL when upstream forwarding times out', async () => {
    jest.useFakeTimers();
    const query = encodeDnsQuery(44, 'slow.example');
    const backend = fakeBackendClient({ action: 'ALLOW' });

    const responsePromise = resolve(query, '10.0.0.5', backend);
    await Promise.resolve();
    jest.advanceTimersByTime(1500);

    const response = await responsePromise;
    expect(response.readUInt16BE(2) & 0x000f).toBe(0x0002); // SERVFAIL
  });

  it('fails open to ALLOW (forwards upstream) when the backend itself is unavailable', async () => {
    // BackendClient.checkPolicy already fails open internally, so a "backend
    // down" scenario looks like checkPolicy resolving with ALLOW.
    const query = encodeDnsQuery(55, 'unknown-policy.example');
    const backend = fakeBackendClient({ action: 'ALLOW' });

    const responsePromise = resolve(query, '10.0.0.5', backend);
    await Promise.resolve();
    await Promise.resolve();
    const upstreamResponse = Buffer.from([1, 1, 1, 1]);
    sockets[0].emit('message', upstreamResponse);

    const response = await responsePromise;
    expect(response).toEqual(upstreamResponse);
  });

  it('propagates a parse error for a malformed packet instead of hanging', async () => {
    const backend = fakeBackendClient({ action: 'ALLOW' });
    await expect(resolve(Buffer.alloc(3), '10.0.0.5', backend)).rejects.toThrow();
  });

  it('keeps concurrent BLOCK requests isolated by DNS transaction id', async () => {
    const ids = [1, 2, 3, 4, 5];
    const backend = fakeBackendClient({ action: 'BLOCK' });

    const queries = ids.map((id) => encodeDnsQuery(id, `blocked${id}.example`));
    const responses = await Promise.all(queries.map((q) => resolve(q, '10.0.0.5', backend)));

    responses.forEach((res, i) => {
      expect(res.readUInt16BE(0)).toBe(ids[i]); // id preserved per-request
    });
    // BLOCK never touches upstream
    expect(dgram.createSocket).not.toHaveBeenCalled();
  });

  it('keeps concurrent ALLOW requests isolated — each gets its own upstream response', async () => {
    const ids = [10, 20, 30];
    const backend = fakeBackendClient({ action: 'ALLOW' });

    const queries = ids.map((id) => encodeDnsQuery(id, `allow${id}.example`));
    const promises = queries.map((q) => resolve(q, '10.0.0.5', backend));

    // Let each resolve() reach the forward stage and create its socket.
    await Promise.resolve();
    await Promise.resolve();
    expect(sockets.length).toBe(ids.length);

    // Answer each socket with a response tagged with a distinct id, in reverse
    // order, to prove responses aren't mixed up between concurrent callers.
    [...sockets].reverse().forEach((s, i) => {
      const tag = Buffer.alloc(2);
      tag.writeUInt16BE(ids[ids.length - 1 - i], 0);
      s.emit('message', tag);
    });

    const responses = await Promise.all(promises);
    responses.forEach((res, i) => {
      expect(res.readUInt16BE(0)).toBe(ids[i]);
    });
  });

  it('handles a large volume of sequential requests without state leaking between them', async () => {
    const backend = fakeBackendClient({ action: 'BLOCK' });
    const total = 500;

    for (let i = 0; i < total; i++) {
      const query = encodeDnsQuery(i % 65536, `host${i}.example`);
      const response = await resolve(query, '10.0.0.5', backend);
      expect(response.readUInt16BE(0)).toBe(i % 65536);
    }

    expect((backend.checkPolicy as jest.Mock)).toHaveBeenCalledTimes(total);
  });

  describe('pairing/beacon probe queries', () => {
    const token = 'a1b2c3d4-e5f6-4789-a012-b3c4d5e6f789';

    it('detects a <token>.pair.guardtime.local probe, confirms it, and never touches policy or upstream', async () => {
      const backend = fakeBackendClient({ action: 'ALLOW' });

      const query = encodeDnsQuery(77, `${token}.pair.guardtime.local`);
      const response = await resolve(query, '203.0.113.9', backend);

      expect((backend as any).confirmPair).toHaveBeenCalledWith(token, '203.0.113.9', undefined);
      expect(backend.checkPolicy).not.toHaveBeenCalled();
      expect(dgram.createSocket).not.toHaveBeenCalled();
      expect(response.readUInt16BE(0)).toBe(77);
      // synthetic ack A record — 127.0.0.1
      expect(response.subarray(response.length - 4).equals(Buffer.from([127, 0, 0, 1]))).toBe(true);
    });

    it('still answers with an ack even when the backend confirm call fails', async () => {
      const backend = fakeBackendClient({ action: 'ALLOW' }, false);

      const query = encodeDnsQuery(88, `${token}.pair.guardtime.local`);
      const response = await resolve(query, '203.0.113.9', backend);

      expect(response.readUInt16BE(0)).toBe(88);
    });

    it('does not treat an ordinary domain as a pairing probe', async () => {
      const backend = fakeBackendClient({ action: 'ALLOW' });

      const query = encodeDnsQuery(99, 'not-a-uuid.pair.guardtime.local');
      await resolve(query, '203.0.113.9', backend);

      expect((backend as any).confirmPair).not.toHaveBeenCalled();
      expect(backend.checkPolicy).toHaveBeenCalled();
    });
  });

  it('handles a large volume of concurrent BLOCK requests correctly', async () => {
    const backend = fakeBackendClient({ action: 'BLOCK' });
    const total = 500;

    const queries = Array.from({ length: total }, (_, i) => encodeDnsQuery(i % 65536, `host${i}.example`));
    const responses = await Promise.all(queries.map((q) => resolve(q, '10.0.0.5', backend)));

    responses.forEach((res, i) => {
      expect(res.readUInt16BE(0)).toBe(i % 65536);
    });
  });
});
