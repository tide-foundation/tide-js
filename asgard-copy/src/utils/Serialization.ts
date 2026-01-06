const base64abc = [
	"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
	"N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
	"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
	"n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/"
];
export function bytesToBase64(bytes: Uint8Array) : string {
	let result = '', i, l = bytes.length;
	for (i = 2; i < l; i += 3) {
		result += base64abc[bytes[i - 2] >> 2];
		result += base64abc[((bytes[i - 2] & 0x03) << 4) | (bytes[i - 1] >> 4)];
		result += base64abc[((bytes[i - 1] & 0x0F) << 2) | (bytes[i] >> 6)];
		result += base64abc[bytes[i] & 0x3F];
	}
	if (i === l + 1) { // 1 octet yet to write
		result += base64abc[bytes[i - 2] >> 2];
		result += base64abc[(bytes[i - 2] & 0x03) << 4];
		result += "==";
	}
	if (i === l) { // 2 octets yet to write
		result += base64abc[bytes[i - 2] >> 2];
		result += base64abc[((bytes[i - 2] & 0x03) << 4) | (bytes[i - 1] >> 4)];
		result += base64abc[(bytes[i - 1] & 0x0F) << 2];
		result += "=";
	}
	return result;
}

export function base64toBytes(base64: string): Uint8Array {
	const lookup: { [key: string]: number } = {};
	for (let i = 0; i < base64abc.length; i++) {
		lookup[base64abc[i]] = i;
	}

	const len = base64.length;
	let bufferLength = base64.length * 0.75;
	if (base64[len - 1] === "=") {
		bufferLength--;
		if (base64[len - 2] === "=") {
			bufferLength--;
		}
	}

	const bytes = new Uint8Array(bufferLength);
	let p = 0;

	for (let i = 0; i < len; i += 4) {
		const encoded1 = lookup[base64[i]];
		const encoded2 = lookup[base64[i + 1]];
		const encoded3 = lookup[base64[i + 2]];
		const encoded4 = lookup[base64[i + 3]];

		bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
		if (encoded3 !== undefined) {
			bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
		}
		if (encoded4 !== undefined) {
			bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
		}
	}

	return bytes;
}

export function StringToUint8Array(string: string) : Uint8Array {
	const enc = new TextEncoder();
	return enc.encode(string);
}
export function StringFromUint8Array(bytes: Uint8Array) : string {
	const enc = new TextDecoder();
	return enc.decode(bytes);
}

export function BigIntToByteArray(value: bigint): Uint8Array {
  if (value < 0n) {
    throw new Error("Negative BigInt values are not supported");
  }

  const bytes: number[] = [];
  let temp = value;

  // Extract bytes in little-endian order
  while (temp > 0n) {
    bytes.push(Number(temp & 0xFFn));
    temp = temp >> 8n;
  }

  // Handle zero case
  if (bytes.length === 0) {
    bytes.push(0);
  }

  // Pad or trim to specified length
  const targetLength = bytes.length;
  const result = new Uint8Array(targetLength);

  for (let i = 0; i < Math.min(bytes.length, targetLength); i++) {
    result[i] = bytes[i];
  }

  return result;
}

export function BigIntFromByteArray(bytes: Uint8Array): bigint {
  let result = 0n;

  // Read bytes in little-endian order
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }

  return result;
}