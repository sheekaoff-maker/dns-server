/**
 * Builds a minimal, valid raw DNS query packet for use in tests.
 * Mirrors the wire format the resolver's parseQuery() expects.
 */
export function encodeDnsQuery(
  id: number,
  domain: string,
  qtype = 1, // A
  qclass = 1, // IN
): Buffer {
  const labels = domain.split('.');
  const nameBuf = Buffer.alloc(domain.length + 2);
  let off = 0;
  for (const label of labels) {
    nameBuf[off++] = label.length;
    nameBuf.write(label, off, 'ascii');
    off += label.length;
  }
  nameBuf[off++] = 0;

  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2); // RD flag
  header.writeUInt16BE(1, 4); // QDCOUNT
  header.writeUInt16BE(0, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);

  const question = Buffer.alloc(4);
  question.writeUInt16BE(qtype, 0);
  question.writeUInt16BE(qclass, 2);

  return Buffer.concat([header, nameBuf.subarray(0, off), question]);
}

export function encodeDnsResponse(id: number, domain: string): Buffer {
  // A minimal, well-formed upstream-style response: header + question + 1 answer.
  const query = encodeDnsQuery(id, domain);
  const answer = Buffer.alloc(16);
  let pos = 0;
  answer.writeUInt16BE(0xc00c, pos); pos += 2; // name ptr
  answer.writeUInt16BE(1, pos); pos += 2; // type A
  answer.writeUInt16BE(1, pos); pos += 2; // class IN
  answer.writeUInt32BE(60, pos); pos += 4; // ttl
  answer.writeUInt16BE(4, pos); pos += 2; // rdlength
  answer.writeUInt32BE(0x08080808, pos); pos += 4; // 8.8.8.8

  const header = Buffer.from(query.subarray(0, 12));
  header.writeUInt16BE(0x8180, 2); // response, no error
  header.writeUInt16BE(1, 6); // ANCOUNT = 1

  return Buffer.concat([header, query.subarray(12), answer.subarray(0, pos)]);
}
