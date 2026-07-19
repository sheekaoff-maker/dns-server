import 'dotenv/config';
import * as dgram from 'dgram';
import { BackendClient } from './backend-client';
import { resolve } from './resolver';
import { startHealthServer } from './health-server';
import { dnsQueriesTotal, dnsResolveDuration } from './metrics';

// The DNS service is co-located with the backend on the same VPS, so it talks
// to the backend over loopback (fast, no TLS/Nginx round-trip on the hot path).
const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:3000';
const DNS_PORT = parseInt(process.env.DNS_PORT || '53', 10);
const HEALTH_PORT = parseInt(process.env.HEALTH_PORT || '8080', 10);

const backendClient = new BackendClient(BACKEND_URL);

const server = dgram.createSocket('udp4');
const healthServer = startHealthServer(HEALTH_PORT, BACKEND_URL);

server.on('message', async (msg: Buffer, rinfo: dgram.RemoteInfo) => {
  const sourceIp = rinfo.address.startsWith('::ffff:')
    ? rinfo.address.substring(7)
    : rinfo.address;

  const start = process.hrtime.bigint();
  try {
    const response = await resolve(msg, sourceIp, backendClient);
    server.send(response, rinfo.port, rinfo.address);
    dnsQueriesTotal.inc({ result: 'resolved' });
  } catch (err: any) {
    console.error(`[ERROR] ${err.message}`);
    dnsQueriesTotal.inc({ result: 'error' });
  } finally {
    dnsResolveDuration.observe(Number(process.hrtime.bigint() - start) / 1e9);
  }
});

server.on('error', (err) => {
  console.error(`[DNS Server] Socket error: ${err.message}`);
});

server.bind(DNS_PORT, '0.0.0.0', () => {
  console.info(`[DNS Server] UDP listening on 0.0.0.0:${DNS_PORT}`);
  console.info(`[DNS Server] Backend: ${BACKEND_URL}`);
  console.info(`[DNS Server] Upstream: ${process.env.UPSTREAM_DNS || '1.1.1.1,8.8.8.8'}`);
});

function shutdown() {
  console.info('[DNS Server] Shutting down...');
  server.close();
  healthServer.close();
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
