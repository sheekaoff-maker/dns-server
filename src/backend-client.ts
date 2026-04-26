import axios from 'axios';

const TIMEOUT_MS = 2000;

export interface PolicyResult {
  action: 'ALLOW' | 'BLOCK';
  blockIp?: string;
  reason?: string;
}

export class BackendClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  async checkPolicy(sourceIp: string, domain: string): Promise<PolicyResult> {
    try {
      const res = await axios.get(`${this.baseUrl}/dns/policy/check`, {
        params: { sourceIp, domain },
        timeout: TIMEOUT_MS,
      });
      return res.data;
    } catch (err: any) {
      console.warn(
        `[BACKEND ERROR] ${err.message} — failing open (ALLOW)`,
      );
      return { action: 'ALLOW' };
    }
  }
}
