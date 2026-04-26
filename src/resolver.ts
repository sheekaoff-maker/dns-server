import * as dns2 from 'dns2';
import { BackendClient } from './backend-client';

const { Packet, UDPClient, TCPClient } = dns2;

const UPSTREAM_DNS_LIST = (process.env.UPSTREAM_DNS || '1.1.1.1,8.8.8.8')
  .split(',')
  .map((s) => s.trim());

function pickUpstream(): string {
  return UPSTREAM_DNS_LIST[Math.floor(Math.random() * UPSTREAM_DNS_LIST.length)];
}

export async function resolve(
  question: any,
  peer: any,
  backendClient: BackendClient,
): Promise<any[]> {
  const domain = question.name as string;
  const qtype = question.type as number;

  const sourceIp = peer?.address || '0.0.0.0';

  const policy = await backendClient.checkPolicy(sourceIp, domain);

  if (policy.action === 'BLOCK') {
    console.info(
      `[BLOCK] domain=${domain} sourceIp=${sourceIp} reason=${policy.reason}`,
    );

    if (qtype === 1) {
      return [{ type: 1, name: domain, address: '0.0.0.0', ttl: 30 }];
    }
    if (qtype === 28) {
      return [{ type: 28, name: domain, address: '::', ttl: 30 }];
    }
    return [];
  }

  console.debug(`[ALLOW] domain=${domain} sourceIp=${sourceIp}`);
  return forwardToUpstream(domain, qtype);
}

async function forwardToUpstream(domain: string, qtype: number): Promise<any[]> {
  const upstream = pickUpstream();

  try {
    const resolve = UDPClient({ dns: upstream, port: 53 });
    const response = await resolve(domain, qtype);
    return response.answers || [];
  } catch (err: any) {
    console.warn(
      `[FORWARD UDP FAILED] domain=${domain} upstream=${upstream}: ${err.message}`,
    );

    try {
      const resolve = TCPClient({ dns: upstream, port: 53 });
      const response = await resolve(domain, qtype);
      return response.answers || [];
    } catch (tcpErr: any) {
      console.error(
        `[FORWARD TCP FAILED] domain=${domain} upstream=${upstream}: ${tcpErr.message}`,
      );
      return [];
    }
  }
}
