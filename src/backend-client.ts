import axios, { AxiosInstance } from 'axios';

export interface DnsPolicyResult {
  action: 'ALLOW' | 'BLOCK';
  blockIp: string;
  reason: string | null;
}

export class BackendClient {
  private client: AxiosInstance;

  constructor(baseUrl: string) {
    this.client = axios.create({
      baseURL: baseUrl,
      timeout: 2000,
    });
  }

  async checkPolicy(sourceIp: string, domain: string): Promise<DnsPolicyResult> {
    try {
      const response = await this.client.get('/dns/policy/check', {
        params: { sourceIp, domain },
      });
      return response.data as DnsPolicyResult;
    } catch (error: any) {
      // On error, ALLOW by default (fail-open) to avoid breaking DNS resolution
      console.error(
        `[BackendClient] Policy check failed for ${domain} from ${sourceIp}: ${error.message}`,
      );
      return { action: 'ALLOW', blockIp: '0.0.0.0', reason: null };
    }
  }
}
