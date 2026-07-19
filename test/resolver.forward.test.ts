import { EventEmitter } from 'events';

jest.mock('dgram', () => ({
  createSocket: jest.fn(),
}));

import * as dgram from 'dgram';
import { forwardToUpstream } from '../src/resolver';
import { encodeDnsQuery } from './helpers/dns-packet';

function makeFakeSocket() {
  const sock: any = new EventEmitter();
  sock.send = jest.fn();
  sock.close = jest.fn();
  return sock;
}

describe('forwardToUpstream', () => {
  let fakeSocket: any;

  beforeEach(() => {
    fakeSocket = makeFakeSocket();
    (dgram.createSocket as jest.Mock).mockReturnValue(fakeSocket);
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.useRealTimers();
  });

  it('resolves with the raw upstream response bytes on message', async () => {
    const query = encodeDnsQuery(5, 'example.com');
    const promise = forwardToUpstream(query);
    const response = Buffer.from([1, 2, 3, 4]);
    fakeSocket.emit('message', response);
    await expect(promise).resolves.toEqual(response);
    expect(fakeSocket.close).toHaveBeenCalledTimes(1);
  });

  it('sends the raw query to port 53 on one of the configured upstreams', async () => {
    const query = encodeDnsQuery(1, 'x.example');
    const promise = forwardToUpstream(query);
    fakeSocket.emit('message', Buffer.from('resp'));
    await promise;
    expect(fakeSocket.send).toHaveBeenCalledWith(
      query,
      53,
      expect.stringMatching(/^1\.1\.1\.1$|^8\.8\.8\.8$/),
    );
  });

  it('rejects when the socket emits an error', async () => {
    const promise = forwardToUpstream(encodeDnsQuery(1, 'x.example'));
    fakeSocket.emit('error', new Error('ENETUNREACH'));
    await expect(promise).rejects.toThrow('ENETUNREACH');
    expect(fakeSocket.close).toHaveBeenCalledTimes(1);
  });

  it('rejects with a timeout error when upstream never responds within 1500ms', async () => {
    jest.useFakeTimers();
    const promise = forwardToUpstream(encodeDnsQuery(1, 'x.example'));
    jest.advanceTimersByTime(1500);
    await expect(promise).rejects.toThrow(/timeout/i);
    expect(fakeSocket.close).toHaveBeenCalledTimes(1);
  });

  it('does not double-settle if a message arrives after the timeout fired', async () => {
    jest.useFakeTimers();
    const promise = forwardToUpstream(encodeDnsQuery(1, 'x.example'));
    jest.advanceTimersByTime(1500);
    await expect(promise).rejects.toThrow();
    expect(() => fakeSocket.emit('message', Buffer.from('late'))).not.toThrow();
  });

  it('does not double-settle if an error arrives after a message already resolved', async () => {
    const promise = forwardToUpstream(encodeDnsQuery(1, 'x.example'));
    fakeSocket.emit('message', Buffer.from('ok'));
    await promise;
    expect(() => fakeSocket.emit('error', new Error('late'))).not.toThrow();
  });

  it('closes the socket exactly once even under rapid repeated events', async () => {
    const promise = forwardToUpstream(encodeDnsQuery(1, 'x.example'));
    fakeSocket.emit('message', Buffer.from('first'));
    fakeSocket.emit('message', Buffer.from('second'));
    fakeSocket.emit('error', new Error('third'));
    await promise;
    expect(fakeSocket.close).toHaveBeenCalledTimes(1);
  });

  it('handles a burst of concurrent forward calls, each with an isolated socket', async () => {
    const sockets: any[] = [];
    (dgram.createSocket as jest.Mock).mockImplementation(() => {
      const s = makeFakeSocket();
      sockets.push(s);
      return s;
    });

    const queries = Array.from({ length: 100 }, (_, i) => encodeDnsQuery(i, `host${i}.example`));
    const promises = queries.map((q) => forwardToUpstream(q));

    sockets.forEach((s, i) => s.emit('message', Buffer.from([i % 256])));

    const results = await Promise.all(promises);
    results.forEach((r, i) => expect(r[0]).toBe(i % 256));
    expect(dgram.createSocket).toHaveBeenCalledTimes(100);
  });
});
