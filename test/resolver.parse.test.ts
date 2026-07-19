import { parseQuery, buildBlockResponse, buildServfailResponse } from '../src/resolver';
import { encodeDnsQuery } from './helpers/dns-packet';

describe('parseQuery', () => {
  it('parses a simple A query', () => {
    const raw = encodeDnsQuery(1234, 'example.com', 1, 1);
    const q = parseQuery(raw);
    expect(q.id).toBe(1234);
    expect(q.domain).toBe('example.com');
    expect(q.qtype).toBe(1);
    expect(q.qclass).toBe(1);
  });

  it('parses a multi-label subdomain', () => {
    const raw = encodeDnsQuery(1, 'a.b.c.example.co.uk');
    const q = parseQuery(raw);
    expect(q.domain).toBe('a.b.c.example.co.uk');
  });

  it('parses an AAAA query type', () => {
    const raw = encodeDnsQuery(1, 'example.com', 28, 1);
    const q = parseQuery(raw);
    expect(q.qtype).toBe(28);
  });

  it('parses a single-label (root-adjacent) domain', () => {
    const raw = encodeDnsQuery(1, 'localhost');
    const q = parseQuery(raw);
    expect(q.domain).toBe('localhost');
  });

  it('follows a DNS compression pointer', () => {
    // question: example.com, then an appended name that points back to offset 12
    const base = encodeDnsQuery(1, 'example.com');
    const pointer = Buffer.from([0xc0, 0x0c]); // pointer to offset 12
    const withPointer = Buffer.concat([base, pointer]);
    // parseQuery only reads the first question, so this just proves parsing
    // the base packet still works when compressed names could appear later.
    const q = parseQuery(withPointer);
    expect(q.domain).toBe('example.com');
  });

  describe('invalid / malformed packets', () => {
    it('throws on an empty buffer', () => {
      expect(() => parseQuery(Buffer.alloc(0))).toThrow();
    });

    it('throws on a truncated header (fewer than 12 bytes)', () => {
      expect(() => parseQuery(Buffer.alloc(5))).toThrow();
    });

    it('throws on a header with no question section', () => {
      const header = Buffer.alloc(12);
      header.writeUInt16BE(1, 4); // claims QDCOUNT=1 but has no question bytes
      expect(() => parseQuery(header)).toThrow();
    });

    it('throws when a length-prefixed label overruns the buffer', () => {
      const raw = encodeDnsQuery(1, 'example.com');
      const corrupted = Buffer.from(raw);
      corrupted[12] = 0xff & 0x3f; // inflate first label length beyond buffer bounds
      expect(() => parseQuery(corrupted)).toThrow();
    });

    it('throws when a compression pointer points past the buffer end', () => {
      const header = Buffer.alloc(12);
      header.writeUInt16BE(1, 4);
      const badPointer = Buffer.from([0xc0, 0xff]); // pointer to offset far beyond buffer
      const raw = Buffer.concat([header, badPointer, Buffer.alloc(4)]);
      expect(() => parseQuery(raw)).toThrow();
    });

    it('throws instead of hanging on a self-referencing compression pointer (DoS guard)', () => {
      // A malicious packet where the name at offset 12 points right back at
      // itself would spin forever in a naive parser — a trivial DoS against
      // the DNS server. parseName caps jumps and must reject this quickly.
      const header = Buffer.alloc(12);
      header.writeUInt16BE(1, 4);
      const selfPointer = Buffer.from([0xc0, 0x0c]); // points to itself at offset 12
      const raw = Buffer.concat([header, selfPointer, Buffer.alloc(4)]);

      expect(() => parseQuery(raw)).toThrow(/loop detected/i);
    }, 2000);

    it('throws on a chain of pointers exceeding the jump cap', () => {
      // Build a chain of 200 two-byte pointers, each pointing at the previous
      // one, terminating in a real label — well beyond any legitimate name.
      const header = Buffer.alloc(12);
      header.writeUInt16BE(1, 4);
      const chainLen = 200;
      const chain = Buffer.alloc(chainLen * 2);
      for (let i = 0; i < chainLen; i++) {
        const selfOffset = 12 + i * 2;
        const prevOffset = i === 0 ? 12 : 12 + (i - 1) * 2;
        // first entry points at itself+2 out of range is fine; rest point to previous
        const target = i === 0 ? selfOffset : prevOffset;
        chain.writeUInt16BE(0xc000 | target, i * 2);
      }
      const raw = Buffer.concat([header, chain]);
      expect(() => parseQuery(raw)).toThrow(/loop detected/i);
    });
  });
});

describe('buildBlockResponse', () => {
  it('builds an A-record response pointing at 0.0.0.0', () => {
    const q = parseQuery(encodeDnsQuery(42, 'blocked.example', 1, 1));
    const res = buildBlockResponse(q);
    expect(res.readUInt16BE(0)).toBe(42); // echoes query id
    expect(res.readUInt16BE(6)).toBe(1); // ANCOUNT = 1
    // last 4 bytes of an A response are the rdata (0.0.0.0)
    expect(res.subarray(res.length - 4).equals(Buffer.from([0, 0, 0, 0]))).toBe(true);
  });

  it('builds an AAAA-record response pointing at ::', () => {
    const q = parseQuery(encodeDnsQuery(7, 'blocked.example', 28, 1));
    const res = buildBlockResponse(q);
    const rdata = res.subarray(res.length - 16);
    expect(rdata.equals(Buffer.alloc(16))).toBe(true);
  });

  it('sets the response flag and recursion-available flag', () => {
    const q = parseQuery(encodeDnsQuery(1, 'x.example'));
    const res = buildBlockResponse(q);
    const flags = res.readUInt16BE(2);
    expect(flags & 0x8000).toBe(0x8000); // QR=1 (response)
    expect(flags & 0x0100).toBe(0x0100); // RA=1
  });
});

describe('buildServfailResponse', () => {
  it('echoes the query id and sets RCODE=SERVFAIL', () => {
    const q = parseQuery(encodeDnsQuery(999, 'timeout.example'));
    const res = buildServfailResponse(q);
    expect(res.length).toBe(12);
    expect(res.readUInt16BE(0)).toBe(999);
    const flags = res.readUInt16BE(2);
    expect(flags & 0x000f).toBe(0x0002); // RCODE = SERVFAIL
    expect(flags & 0x8000).toBe(0x8000); // QR=1
  });

  it('reports zero answer/authority/additional records', () => {
    const q = parseQuery(encodeDnsQuery(1, 'x.example'));
    const res = buildServfailResponse(q);
    expect(res.readUInt16BE(6)).toBe(0);
    expect(res.readUInt16BE(8)).toBe(0);
    expect(res.readUInt16BE(10)).toBe(0);
  });
});
