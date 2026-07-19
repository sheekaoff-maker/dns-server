import * as http from 'http';
import axios from 'axios';
import { startHealthServer } from '../src/health-server';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

function request(port: number, path: string): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    http.get(`http://127.0.0.1:${port}${path}`, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        resolve({ status: res.statusCode || 0, body: JSON.parse(data) });
      });
    }).on('error', reject);
  });
}

function requestText(port: number, path: string): Promise<{ status: number; body: string; contentType?: string }> {
  return new Promise((resolve, reject) => {
    http.get(`http://127.0.0.1:${port}${path}`, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        resolve({ status: res.statusCode || 0, body: data, contentType: res.headers['content-type'] });
      });
    }).on('error', reject);
  });
}

describe('health-server', () => {
  let server: http.Server;
  let port: number;

  beforeEach((done) => {
    jest.clearAllMocks();
    server = startHealthServer(0, 'http://127.0.0.1:3000');
    server.on('listening', () => {
      port = (server.address() as any).port;
      done();
    });
  });

  afterEach((done) => {
    server.close(() => done());
  });

  it('GET /health always returns 200 ok (liveness)', async () => {
    const res = await request(port, '/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  it('GET /health/live also returns 200 ok', async () => {
    const res = await request(port, '/health/live');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });

  it('GET /health/ready returns 200 when the backend is reachable', async () => {
    mockedAxios.get.mockResolvedValueOnce({ data: { status: 'ok' } });
    const res = await request(port, '/health/ready');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ready', backend: 'reachable' });
    expect(mockedAxios.get).toHaveBeenCalledWith(
      'http://127.0.0.1:3000/health',
      expect.objectContaining({ timeout: 1500 }),
    );
  });

  it('GET /health/ready returns 503 when the backend is unreachable', async () => {
    mockedAxios.get.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    const res = await request(port, '/health/ready');
    expect(res.status).toBe(503);
    expect(res.body.status).toBe('degraded');
    expect(res.body.backend).toBe('unreachable');
  });

  it('GET /metrics returns Prometheus text format', async () => {
    const res = await requestText(port, '/metrics');
    expect(res.status).toBe(200);
    expect(res.contentType).toMatch(/text\/plain/);
    expect(res.body).toMatch(/# HELP dns_queries_total/);
    expect(res.body).toMatch(/# TYPE dns_resolve_duration_seconds histogram/);
    expect(res.body).toMatch(/guardtime_dns_process_resident_memory_bytes/);
  });

  it('returns 404 for unknown paths', async () => {
    const res = await request(port, '/nope');
    expect(res.status).toBe(404);
  });

  it('strips a trailing slash from the backend URL before building the health check URL', async () => {
    server.close();
    server = startHealthServer(0, 'http://127.0.0.1:3000/');
    await new Promise<void>((resolve) => server.on('listening', () => resolve()));
    port = (server.address() as any).port;

    mockedAxios.get.mockResolvedValueOnce({ data: {} });
    await request(port, '/health/ready');
    expect(mockedAxios.get).toHaveBeenCalledWith(
      'http://127.0.0.1:3000/health',
      expect.anything(),
    );
  });
});
