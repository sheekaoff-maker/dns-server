declare module 'dns2' {
  export class Packet {
    static createResponseFromRequest(request: any): any;
    static TYPE: { A: number; AAAA: number; NS: number; CNAME: number; MX: number; TXT: number };
  }

  export interface UpstreamOptions {
    dns: string;
    port?: number;
  }

  export function UDPClient(options: UpstreamOptions): (domain: string, type: number) => Promise<{ answers: any[] }>;
  export function TCPClient(options: UpstreamOptions): (domain: string, type: number) => Promise<{ answers: any[] }>;

  export class UDPServer {
    constructor(handler: (request: any, send: (response: any) => void, peer: any) => void | Promise<void>);
    listen(port: number, host: string, callback?: () => void): void;
    close(): void;
  }

  export class TCPServer {
    constructor(handler: (request: any, send: (response: any) => void, peer: any) => void | Promise<void>);
    listen(port: number, host: string, callback?: () => void): void;
    close(): void;
  }
}
