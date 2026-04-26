import 'dotenv/config';
import * as dgram from 'dgram';
import { BackendClient } from './backend-client';
import { resolve } from './resolver';

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:3000';
const DNS_PORT = parseInt(process.env.DNS_PORT || '53', 10);

const backendClient = new BackendClient(BACKEND_URL);

const server = dgram.createSocket('udp4');

server.on('message', async (msg: Buffer, rinfo: dgram.RemoteInfo) => {
  const sourceIp = rinfo.address.startsWith('::ffff:')
    ? rinfo.address.substring(7)
    : rinfo.address;

  try {
    const response = await resolve(msg, sourceIp, backendClient);
    server.send(response, rinfo.port, rinfo.address);
  } catch (err: any) {
    console.error(`[ERROR] ${err.message}`);
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

process.on('SIGTERM', () => {
  console.info('[DNS Server] Shutting down...');
  server.close();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.info('[DNS Server] Shutting down...');
  server.close();
  process.exit(0);
});
