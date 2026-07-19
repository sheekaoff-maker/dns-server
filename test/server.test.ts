import { EventEmitter } from 'events';

jest.mock('dgram', () => ({
  createSocket: jest.fn(),
}));
jest.mock('../src/resolver', () => ({
  resolve: jest.fn(),
}));
jest.mock('../src/health-server', () => ({
  startHealthServer: jest.fn(() => ({ close: jest.fn() })),
}));
jest.mock('../src/metrics', () => ({
  dnsQueriesTotal: { inc: jest.fn() },
  dnsResolveDuration: { observe: jest.fn() },
}));

import * as dgram from 'dgram';
import { resolve } from '../src/resolver';
import { startHealthServer } from '../src/health-server';
import { dnsQueriesTotal, dnsResolveDuration } from '../src/metrics';

function makeFakeSocket() {
  const sock: any = new EventEmitter();
  sock.send = jest.fn();
  sock.close = jest.fn();
  sock.bind = jest.fn((_port: number, _host: string, cb?: () => void) => cb && cb());
  return sock;
}

describe('server.ts (UDP wiring)', () => {
  let fakeSocket: any;
  let exitSpy: jest.SpyInstance;
  let errorSpy: jest.SpyInstance;

  beforeAll(() => {
    fakeSocket = makeFakeSocket();
    (dgram.createSocket as jest.Mock).mockReturnValue(fakeSocket);
    exitSpy = jest.spyOn(process, 'exit').mockImplementation(() => undefined as never);
    jest.spyOn(console, 'info').mockImplementation(() => {});
    errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    // Module has import-time side effects (creates + binds the socket), so it
    // must be required exactly once, after the mocks above are in place.
    require('../src/server');
  });

  beforeEach(() => {
    (resolve as jest.Mock).mockReset();
    fakeSocket.send.mockClear();
    fakeSocket.close.mockClear();
    exitSpy.mockClear();
    errorSpy.mockClear();
    (dnsQueriesTotal.inc as jest.Mock).mockClear();
    (dnsResolveDuration.observe as jest.Mock).mockClear();
  });

  afterAll(() => {
    jest.restoreAllMocks();
    process.removeAllListeners('SIGTERM');
    process.removeAllListeners('SIGINT');
  });

  it('binds a UDP socket on 0.0.0.0 with the configured port', () => {
    expect(fakeSocket.bind).toHaveBeenCalledWith(expect.any(Number), '0.0.0.0', expect.any(Function));
  });

  it('resolves an incoming query and sends the response back to the client', async () => {
    (resolve as jest.Mock).mockResolvedValue(Buffer.from([1, 2, 3]));

    fakeSocket.emit('message', Buffer.from('query'), { address: '10.0.0.9', port: 5000 });
    await Promise.resolve();
    await Promise.resolve();

    expect(fakeSocket.send).toHaveBeenCalledWith(Buffer.from([1, 2, 3]), 5000, '10.0.0.9');
    expect(dnsQueriesTotal.inc).toHaveBeenCalledWith({ result: 'resolved' });
    expect(dnsResolveDuration.observe).toHaveBeenCalledWith(expect.any(Number));
  });

  it('strips the IPv4-mapped IPv6 prefix from the source address before resolving', async () => {
    (resolve as jest.Mock).mockResolvedValue(Buffer.from([9]));

    fakeSocket.emit('message', Buffer.from('query'), { address: '::ffff:10.0.0.9', port: 5000 });
    await Promise.resolve();
    await Promise.resolve();

    expect(resolve).toHaveBeenCalledWith(expect.any(Buffer), '10.0.0.9', expect.anything());
  });

  it('logs and swallows errors thrown while resolving instead of crashing', async () => {
    (resolve as jest.Mock).mockRejectedValue(new Error('boom'));

    fakeSocket.emit('message', Buffer.from('query'), { address: '10.0.0.1', port: 1 });
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('boom'));
    expect(fakeSocket.send).not.toHaveBeenCalled();
    expect(dnsQueriesTotal.inc).toHaveBeenCalledWith({ result: 'error' });
    expect(dnsResolveDuration.observe).toHaveBeenCalledWith(expect.any(Number));
  });

  it('logs socket-level errors without crashing the process', () => {
    expect(() => fakeSocket.emit('error', new Error('EADDRINUSE'))).not.toThrow();
  });

  it('closes the socket and exits cleanly on SIGTERM', () => {
    process.emit('SIGTERM' as NodeJS.Signals);
    expect(fakeSocket.close).toHaveBeenCalled();
    expect(exitSpy).toHaveBeenCalledWith(0);
  });

  it('closes the socket and exits cleanly on SIGINT', () => {
    process.emit('SIGINT' as NodeJS.Signals);
    expect(fakeSocket.close).toHaveBeenCalled();
    expect(exitSpy).toHaveBeenCalledWith(0);
  });
});
