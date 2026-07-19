import axios from 'axios';
import { BackendClient } from '../src/backend-client';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('BackendClient', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('strips a trailing slash from the base URL', async () => {
    mockedAxios.get.mockResolvedValueOnce({ data: { action: 'ALLOW' } });
    const client = new BackendClient('http://127.0.0.1:3000/');
    await client.checkPolicy('10.0.0.5', 'example.com');
    expect(mockedAxios.get).toHaveBeenCalledWith(
      'http://127.0.0.1:3000/dns/policy/check',
      expect.anything(),
    );
  });

  it('returns ALLOW when backend allows the domain', async () => {
    mockedAxios.get.mockResolvedValueOnce({ data: { action: 'ALLOW' } });
    const client = new BackendClient('http://127.0.0.1:3000');
    const result = await client.checkPolicy('10.0.0.5', 'example.com');
    expect(result).toEqual({ action: 'ALLOW' });
  });

  it('returns BLOCK with a reason when backend blocks the domain', async () => {
    mockedAxios.get.mockResolvedValueOnce({
      data: { action: 'BLOCK', reason: 'category:adult' },
    });
    const client = new BackendClient('http://127.0.0.1:3000');
    const result = await client.checkPolicy('10.0.0.5', 'blocked.example');
    expect(result).toEqual({ action: 'BLOCK', reason: 'category:adult' });
  });

  it('passes sourceIp and domain as query params', async () => {
    mockedAxios.get.mockResolvedValueOnce({ data: { action: 'ALLOW' } });
    const client = new BackendClient('http://127.0.0.1:3000');
    await client.checkPolicy('192.168.1.42', 'kids-safe.example');
    expect(mockedAxios.get).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        params: { sourceIp: '192.168.1.42', domain: 'kids-safe.example' },
      }),
    );
  });

  it('enforces a 2000ms request timeout', async () => {
    mockedAxios.get.mockResolvedValueOnce({ data: { action: 'ALLOW' } });
    const client = new BackendClient('http://127.0.0.1:3000');
    await client.checkPolicy('10.0.0.5', 'example.com');
    expect(mockedAxios.get).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ timeout: 2000 }),
    );
  });

  it('fails open (ALLOW) when the backend is unreachable (connection refused)', async () => {
    mockedAxios.get.mockRejectedValueOnce(
      Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }),
    );
    const client = new BackendClient('http://127.0.0.1:3000');
    const result = await client.checkPolicy('10.0.0.5', 'example.com');
    expect(result).toEqual({ action: 'ALLOW' });
  });

  it('fails open (ALLOW) when the backend request times out', async () => {
    mockedAxios.get.mockRejectedValueOnce(
      Object.assign(new Error('timeout of 2000ms exceeded'), { code: 'ECONNABORTED' }),
    );
    const client = new BackendClient('http://127.0.0.1:3000');
    const result = await client.checkPolicy('10.0.0.5', 'example.com');
    expect(result).toEqual({ action: 'ALLOW' });
  });

  it('fails open (ALLOW) when the backend returns a 5xx error', async () => {
    mockedAxios.get.mockRejectedValueOnce(
      Object.assign(new Error('Request failed with status code 500'), {
        response: { status: 500 },
      }),
    );
    const client = new BackendClient('http://127.0.0.1:3000');
    const result = await client.checkPolicy('10.0.0.5', 'example.com');
    expect(result).toEqual({ action: 'ALLOW' });
  });

  it('logs the failure reason when failing open', async () => {
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    mockedAxios.get.mockRejectedValueOnce(new Error('network down'));
    const client = new BackendClient('http://127.0.0.1:3000');
    await client.checkPolicy('10.0.0.5', 'example.com');
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('network down'));
  });

  it('does not cache results — identical repeated lookups each hit the backend', async () => {
    mockedAxios.get.mockResolvedValue({ data: { action: 'ALLOW' } });
    const client = new BackendClient('http://127.0.0.1:3000');
    await client.checkPolicy('10.0.0.5', 'example.com');
    await client.checkPolicy('10.0.0.5', 'example.com');
    await client.checkPolicy('10.0.0.5', 'example.com');
    // No caching layer exists in BackendClient today — every call is a network round trip.
    expect(mockedAxios.get).toHaveBeenCalledTimes(3);
  });

  it('handles a burst of concurrent policy checks independently', async () => {
    mockedAxios.get.mockImplementation((_url: string, config: any) =>
      Promise.resolve({
        data: config.params.domain.startsWith('blocked')
          ? { action: 'BLOCK' }
          : { action: 'ALLOW' },
      }),
    );
    const client = new BackendClient('http://127.0.0.1:3000');
    const domains = Array.from({ length: 50 }, (_, i) =>
      i % 5 === 0 ? `blocked${i}.example` : `allowed${i}.example`,
    );
    const results = await Promise.all(
      domains.map((d) => client.checkPolicy('10.0.0.5', d)),
    );
    results.forEach((r, i) => {
      expect(r.action).toBe(domains[i].startsWith('blocked') ? 'BLOCK' : 'ALLOW');
    });
  });
});
