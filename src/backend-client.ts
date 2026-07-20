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

  /**
   * Fire-and-forget-ish confirm for a resolved pairing/beacon probe query.
   * Errors are swallowed (logged) — the probe's UDP reply to the parent app
   * is synthetic either way (see resolver.ts), so a failed confirm here
   * just means the app's next status poll shows still-WAITING, not a crash.
   */
  async confirmPair(token: string, sourceIp: string, resolverRegion?: string): Promise<boolean> {
    try {
      await axios.post(
        `${this.baseUrl}/dns/pair/confirm`,
        { token, sourceIp, resolverRegion },
        { timeout: TIMEOUT_MS },
      );
      return true;
    } catch (err: any) {
      console.warn(`[PAIR CONFIRM FAILED] token=${token.slice(0, 8)}… sourceIp=${sourceIp}: ${err.message}`);
      return false;
    }
  }
}
