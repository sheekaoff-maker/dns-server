import * as dns2 from 'dns2';
import { BackendClient } from './backend-client';

const { Packet, UDPClient, TCPClient } = dns2;

const UPSTREAM_DNS_LIST = (process.env.UPSTREAM_DNS || '1.1.1.1,8.8.8.8')
  .split(',')
  .map((s) => s.trim());

function pickUpstream(): string {
  return UPSTREAM_DNS_LIST[Math.floor(Math.random() * UPSTREAM_DNS_LIST.length)];
}

export class Resolver extends dns2.Resolver {
  private backendClient: BackendClient;

  constructor(backendClient: BackendClient) {
    super();
    this.backendClient = backendClient;
  }

  async resolve(question: any, peer: any): Promise<any[]> {
    const domain = question.name as string;
    const qtype = question.type as number;

    // Extract source IP from the peer address
    const sourceIp = peer?.address || '0.0.0.0';

    // Check DNS policy with backend
    const policy = await this.backendClient.checkPolicy(sourceIp, domain);

    if (policy.action === 'BLOCK') {
      console.info(
        `[BLOCK] domain=${domain} sourceIp=${sourceIp} reason=${policy.reason}`,
      );

      if (qtype === Packet.TYPE.A) {
        return [{ type: Packet.TYPE.A, name: domain, address: '0.0.0.0', ttl: 30 }];
      }
      if (qtype === Packet.TYPE.AAAA) {
        return [{ type: Packet.TYPE.AAAA, name: domain, address: '::', ttl: 30 }];
      }
      // For other record types, return empty (NXDOMAIN-like)
      return [];
    }

    // ALLOW: forward to upstream DNS
    console.debug(`[ALLOW] domain=${domain} sourceIp=${sourceIp}`);
    return this.forwardToUpstream(question);
  }

  private async forwardToUpstream(question: any): Promise<any[]> {
    const upstream = pickUpstream();

    const transport = new UDPClient(upstream);

    try {
      const response = await transport.resolve(question);
      return response.answers;
    } catch (err: any) {
      console.warn(
        `[FORWARD FAILED] domain=${question.name} upstream=${upstream}: ${err.message}`,
      );

      // Try TCP fallback
      try {
        const tcpTransport = new TCPClient(upstream);
        const response = await tcpTransport.resolve(question);
        return response.answers;
      } catch (tcpErr: any) {
        console.error(
          `[FORWARD TCP FAILED] domain=${question.name} upstream=${upstream}: ${tcpErr.message}`,
        );
        return [];
      }
    }
  }
}
