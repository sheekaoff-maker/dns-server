import 'dotenv/config';
import * as dns2 from 'dns2';
import { BackendClient } from './backend-client';
import { resolve } from './resolver';

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:3000';
const DNS_PORT = parseInt(process.env.DNS_PORT || '53', 10);

const backendClient = new BackendClient(BACKEND_URL);

const server = new dns2.UDPServer(async (request: any, send: any, peer: any) => {
  const response = dns2.Packet.createResponseFromRequest(request);

  for (const question of request.questions) {
    try {
      const answers = await resolve(question, peer, backendClient);
      response.answers.push(...answers);
    } catch (err: any) {
      console.error(`[ERROR] Failed to resolve ${question.name}: ${err.message}`);
    }
  }

  send(response);
});

server.listen(DNS_PORT, '0.0.0.0', () => {
  console.info(
    `[DNS Server] Listening on UDP port ${DNS_PORT} (0.0.0.0)`,
  );
  console.info(`[DNS Server] Backend: ${BACKEND_URL}`);
  console.info(
    `[DNS Server] Upstream: ${process.env.UPSTREAM_DNS || '1.1.1.1,8.8.8.8'}`,
  );
});

const tcpServer = new dns2.TCPServer(async (request: any, send: any, peer: any) => {
  const response = dns2.Packet.createResponseFromRequest(request);

  for (const question of request.questions) {
    try {
      const answers = await resolve(question, peer, backendClient);
      response.answers.push(...answers);
    } catch (err: any) {
      console.error(`[ERROR] Failed to resolve ${question.name}: ${err.message}`);
    }
  }

  send(response);
});

tcpServer.listen(DNS_PORT, '0.0.0.0', () => {
  console.info(
    `[DNS Server] Listening on TCP port ${DNS_PORT} (0.0.0.0)`,
  );
});

process.on('SIGTERM', () => {
  console.info('[DNS Server] Shutting down...');
  server.close();
  tcpServer.close();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.info('[DNS Server] Shutting down...');
  server.close();
  tcpServer.close();
  process.exit(0);
});
