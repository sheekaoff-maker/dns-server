declare module 'dns2' {
  export class Packet {
    static createResponseFromRequest(request: any): any;
    static TYPE: { A: number; AAAA: number; NS: number; CNAME: number; MX: number; TXT: number };
  }

  export class Resolver {
    resolve(question: any, peer?: any): Promise<any[]>;
  }

  export class UDPClient {
    constructor(host: string);
    resolve(question: any): Promise<any>;
  }

  export class TCPClient {
    constructor(host: string);
    resolve(question: any): Promise<any>;
  }

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
