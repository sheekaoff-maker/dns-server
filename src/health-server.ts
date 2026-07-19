import * as http from 'http';
import axios from 'axios';
import { registry } from './metrics';

const READY_TIMEOUT_MS = 1500;

/**
 * Minimal HTTP health/readiness/metrics surface for the DNS service. The
 * service's actual job runs entirely over UDP/TCP port 53, which
 * orchestrators (Docker, Kubernetes, systemd) and Prometheus can't probe
 * directly — this gives them a real HTTP endpoint to hit instead.
 */
export function startHealthServer(port: number, backendUrl: string): http.Server {
  const server = http.createServer(async (req, res) => {
    if (req.url === '/health' || req.url === '/health/live') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok' }));
      return;
    }

    if (req.url === '/metrics') {
      res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' });
      res.end(await registry.metrics());
      return;
    }

    if (req.url === '/health/ready') {
      try {
        await axios.get(`${backendUrl.replace(/\/$/, '')}/health`, {
          timeout: READY_TIMEOUT_MS,
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ready', backend: 'reachable' }));
      } catch (err: any) {
        // Not ready to serve, but not down either — resolve() itself fails
        // open (ALLOW) when the backend is unreachable, so DNS keeps working;
        // readiness just reflects that the policy backend is currently out.
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'degraded', backend: 'unreachable', error: err.message }));
      }
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
  });

  server.listen(port, '0.0.0.0', () => {
    console.info(`[Health Server] HTTP listening on 0.0.0.0:${port} (/health, /health/ready)`);
  });

  return server;
}
