// TLS presentation-language encoding as used by MLS (RFC 9420 section 2.1),
// including MLS's variable-length integer for vector lengths. Every signed
// structure in Agent Bridge uses this encoding — never ad-hoc concatenation.

export class DecodeError extends Error {
  override name = 'DecodeError';
}

const MAX_VARINT = 0x3fff_ffff; // 2^30 - 1

export class TlsWriter {
  #parts: Uint8Array[] = [];

  u8(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > 0xff) throw new RangeError('u8 out of range');
    this.#parts.push(Uint8Array.of(value));
    return this;
  }

  u16(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new RangeError('u16 out of range');
    this.#parts.push(Uint8Array.of(value >>> 8, value & 0xff));
    return this;
  }

  u32(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) throw new RangeError('u32 out of range');
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value);
    this.#parts.push(out);
    return this;
  }

  u64(value: bigint | number): this {
    const v = BigInt(value);
    if (v < 0n || v > 0xffff_ffff_ffff_ffffn) throw new RangeError('u64 out of range');
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, v);
    this.#parts.push(out);
    return this;
  }

  /** MLS variable-length integer, minimal encoding. */
  varint(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > MAX_VARINT) throw new RangeError('varint out of range');
    if (value < 0x40) this.#parts.push(Uint8Array.of(value));
    else if (value < 0x4000) this.#parts.push(Uint8Array.of(0x40 | (value >>> 8), value & 0xff));
    else {
      this.#parts.push(
        Uint8Array.of(0x80 | ((value >>> 24) & 0x3f), (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff),
      );
    }
    return this;
  }

  /** `opaque data<V>`: varint length prefix, then the bytes. */
  opaque(bytes: Uint8Array): this {
    this.varint(bytes.length);
    this.#parts.push(bytes);
    return this;
  }

  finish(): Uint8Array {
    const total = this.#parts.reduce((sum, p) => sum + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of this.#parts) {
      out.set(p, offset);
      offset += p.length;
    }
    return out;
  }
}

export class TlsReader {
  #buf: Uint8Array;
  #view: DataView;
  #pos = 0;

  constructor(buf: Uint8Array) {
    this.#buf = buf;
    this.#view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  get offset(): number {
    return this.#pos;
  }

  get remaining(): number {
    return this.#buf.length - this.#pos;
  }

  #need(n: number): void {
    if (this.remaining < n) throw new DecodeError('unexpected end of input');
  }

  u8(): number {
    this.#need(1);
    return this.#view.getUint8(this.#pos++);
  }

  u16(): number {
    this.#need(2);
    const v = this.#view.getUint16(this.#pos);
    this.#pos += 2;
    return v;
  }

  u32(): number {
    this.#need(4);
    const v = this.#view.getUint32(this.#pos);
    this.#pos += 4;
    return v;
  }

  u64(): bigint {
    this.#need(8);
    const v = this.#view.getBigUint64(this.#pos);
    this.#pos += 8;
    return v;
  }

  varint(): number {
    const first = this.u8();
    const prefix = first >>> 6;
    if (prefix === 0) return first & 0x3f;
    if (prefix === 1) {
      const v = ((first & 0x3f) << 8) | this.u8();
      if (v < 0x40) throw new DecodeError('non-minimal varint');
      return v;
    }
    if (prefix === 2) {
      this.#need(3);
      const v = (((first & 0x3f) << 24) | (this.u8() << 16) | (this.u8() << 8) | this.u8()) >>> 0;
      if (v < 0x4000) throw new DecodeError('non-minimal varint');
      return v;
    }
    throw new DecodeError('invalid varint prefix');
  }

  bytes(n: number): Uint8Array {
    this.#need(n);
    const out = this.#buf.subarray(this.#pos, this.#pos + n);
    this.#pos += n;
    return out;
  }

  opaque(): Uint8Array {
    return this.bytes(this.varint());
  }

  /** The rest of the input, without consuming it. */
  rest(): Uint8Array {
    return this.#buf.subarray(this.#pos);
  }

  end(): void {
    if (this.remaining !== 0) throw new DecodeError(`${this.remaining} trailing bytes`);
  }
}
