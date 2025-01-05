// Minimal function to generate the signature and Base64 URL-encoded stamp
import * as Bytes from "./bytes";
export async function generateApiKeyStamp(jsonBody: string, publicKey: string, privateKey: string): Promise<string> {
  // Import the key pair (from hex string)
  const key = await importApiKey(privateKey, publicKey);
  console.log("key", key)

  // Sign the JSON body with the private key
  const signature = await signMessage(key, jsonBody);
  console.log("signature", signature)

  // Create the stamp object
  const stamp = {
    publicKey: publicKey,
    signature: signature,
    scheme: "SIGNATURE_SCHEME_TK_API_P256"
  };

  // Convert the stamp to a Base64 URL encoded string
  const stampBase64Url = stringToBase64urlString(JSON.stringify(stamp));

  // Log the result (the "X-Stamp" header value)
  console.log("Generated X-Stamp:", stampBase64Url);
  return stampBase64Url;
}

// Import the private and public key into a CryptoKey object
async function importApiKey(privateKeyHex: string, publicKeyHex: string): Promise<CryptoKey> {
  const jwk = convertTurnkeyApiKeyToJwk({
    uncompressedPrivateKeyHex: privateKeyHex,
    compressedPublicKeyHex: publicKeyHex
  });

  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
}

function toUnsignedBigNum(bytes: Uint8Array): Uint8Array {
  // Remove zero prefixes.
  let start = 0;
  while (start < bytes.length && bytes[start] == 0) {
    start++;
  }
  if (start == bytes.length) {
    start = bytes.length - 1;
  }
  let extraZero = 0;

  // If the 1st bit is not zero, add 1 zero byte.
  if ((bytes[start]! & 128) == 128) {
    // Add extra zero.
    extraZero = 1;
  }
  const res = new Uint8Array(bytes.length - start + extraZero);
  res.set(bytes.subarray(start), extraZero);
  return res;
}

function convertEcdsaIeee1363ToDer(ieee: Uint8Array): Uint8Array {
  if (ieee.length % 2 != 0 || ieee.length == 0 || ieee.length > 132) {
    throw new Error(
      "Invalid IEEE P1363 signature encoding. Length: " + ieee.length
    );
  }
  const r = toUnsignedBigNum(ieee.subarray(0, ieee.length / 2));
  const s = toUnsignedBigNum(ieee.subarray(ieee.length / 2, ieee.length));
  let offset = 0;
  const length = 1 + 1 + r.length + 1 + 1 + s.length;
  let der;
  if (length >= 128) {
    der = new Uint8Array(length + 3);
    der[offset++] = 48;
    der[offset++] = 128 + 1;
    der[offset++] = length;
  } else {
    der = new Uint8Array(length + 2);
    der[offset++] = 48;
    der[offset++] = length;
  }
  der[offset++] = 2;
  der[offset++] = r.length;
  der.set(r, offset);
  offset += r.length;
  der[offset++] = 2;
  der[offset++] = s.length;
  der.set(s, offset);
  return der;
}

// Sign the JSON body (string) with the private key
async function signMessage(key: CryptoKey, content: string): Promise<string> {
  const signatureIeee1363 = await crypto.subtle.sign(
    {
      name: "ECDSA",
      hash: "SHA-256",
    },
    key,
    new TextEncoder().encode(content)
  );

  const signatureDer = convertEcdsaIeee1363ToDer(
    new Uint8Array(signatureIeee1363)
  );

  return uint8ArrayToHexString(signatureDer);
}

// sdk reference
function fieldSizeInBytes(): number {
  return 32;
}

function byteArrayToInteger(bytes: Uint8Array): bigint {
  return BigInt("0x" + Bytes.toHex(bytes));
}

function getModulus(): bigint {
  // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf (Appendix D).
  return BigInt(
    "115792089210356248762697446949407573530086143415290314195533631308" +
    "867097853951"
  );
}

function testBit(n: bigint, i: number): boolean {
  const m = BigInt(1) << BigInt(i);
  return (n & m) !== BigInt(0);
}

function modPow(b: bigint, exp: bigint, p: bigint): bigint {
  if (exp === BigInt(0)) {
    return BigInt(1);
  }
  let result = b;
  const exponentBitString = exp.toString(2);
  for (let i = 1; i < exponentBitString.length; ++i) {
    result = (result * result) % p;
    if (exponentBitString[i] === "1") {
      result = (result * b) % p;
    }
  }
  return result;
}

function modSqrt(x: bigint, p: bigint): bigint {
  if (p <= BigInt(0)) {
    throw new Error("p must be positive");
  }
  const base = x % p;
  // The currently supported NIST curves P-256, P-384, and P-521 all satisfy
  // p % 4 == 3.  However, although currently a no-op, the following check
  // should be left in place in case other curves are supported in the future.
  if (testBit(p, 0) && /* istanbul ignore next */ testBit(p, 1)) {
    // Case p % 4 == 3 (applies to NIST curves P-256, P-384, and P-521)
    // q = (p + 1) / 4
    const q = (p + BigInt(1)) >> BigInt(2);
    const squareRoot = modPow(base, q, p);
    if ((squareRoot * squareRoot) % p !== base) {
      throw new Error("could not find a modular square root");
    }
    return squareRoot;
  }
  // Skipping other elliptic curve types that require Cipolla's algorithm.
  throw new Error("unsupported modulus value");
}

function getY(x: bigint, lsb: boolean): bigint {
  const p = getModulus();
  const a = p - BigInt(3);
  const b = getB();
  const rhs = ((x * x + a) * x + b) % p;
  let y = modSqrt(rhs, p);
  if (lsb !== testBit(y, 0)) {
    y = (p - y) % p;
  }
  return y;
}

function getB(): bigint {
  // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf (Appendix D).
  return BigInt(
    "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
  );
}

function integerToByteArray(i: bigint, length: number): Uint8Array {
  const input = i.toString(16);
  const numHexChars = length * 2;
  let padding = "";
  if (numHexChars < input.length) {
    throw new Error(
      `cannot pack integer with ${input.length} hex chars into ${length} bytes`
    );
  } else {
    padding = "0".repeat(numHexChars - input.length);
  }
  return Bytes.fromHex(padding + input);
}

function isP256CurvePoint(x: bigint, y: bigint): boolean {
  const p = getModulus();
  const a = p - BigInt(3);
  const b = getB();
  const rhs = ((x * x + a) * x + b) % p;
  const lhs = y ** BigInt(2) % p;
  return lhs === rhs;
}

function pointDecode(point: Uint8Array): JsonWebKey {
  const fieldSize = fieldSizeInBytes();
  const compressedLength = fieldSize + 1;
  const uncompressedLength = 2 * fieldSize + 1;
  if (
    point.length !== compressedLength &&
    point.length !== uncompressedLength
  ) {
    throw new Error(
      "Invalid length: point is not in compressed or uncompressed format"
    );
  }
  // Decodes point if its length and first bit match the compressed format
  if ((point[0] === 2 || point[0] === 3) && point.length == compressedLength) {
    const lsb = point[0] === 3; // point[0] must be 2 (false) or 3 (true).
    const x = byteArrayToInteger(point.subarray(1, point.length));
    const p = getModulus();
    if (x < BigInt(0) || x >= p) {
      throw new Error("x is out of range");
    }
    const y = getY(x, lsb);
    const result: JsonWebKey = {
      kty: "EC",
      crv: "P-256",
      x: Bytes.toBase64(integerToByteArray(x, 32), /* websafe */ true),
      y: Bytes.toBase64(integerToByteArray(y, 32), /* websafe */ true),
      ext: true,
    };
    return result;
    // Decodes point if its length and first bit match the uncompressed format
  } else if (point[0] === 4 && point.length == uncompressedLength) {
    const x = byteArrayToInteger(point.subarray(1, fieldSize + 1));
    const y = byteArrayToInteger(
      point.subarray(fieldSize + 1, 2 * fieldSize + 1)
    );
    const p = getModulus();
    if (
      x < BigInt(0) ||
      x >= p ||
      y < BigInt(0) ||
      y >= p ||
      !isP256CurvePoint(x, y)
    ) {
      throw new Error("invalid uncompressed x and y coordinates");
    }
    const result: JsonWebKey = {
      kty: "EC",
      crv: "P-256",
      x: Bytes.toBase64(integerToByteArray(x, 32), /* websafe */ true),
      y: Bytes.toBase64(integerToByteArray(y, 32), /* websafe */ true),
      ext: true,
    };
    return result;
  }
  throw new Error("invalid format");
}

const DEFAULT_JWK_MEMBER_BYTE_LENGTH = 32;

function base64StringToBase64UrlEncodedString(input: string): string {
  return input.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function uint8ArrayToHexString(input: Uint8Array): string {
  return input.reduce(
    (result, x) => result + x.toString(16).padStart(2, "0"),
    ""
  );
}

const uint8ArrayFromHexString = (
  hexString: string,
  length?: number
): Uint8Array => {
  const hexRegex = /^[0-9A-Fa-f]+$/;
  if (!hexString || hexString.length % 2 != 0 || !hexRegex.test(hexString)) {
    throw new Error(
      `cannot create uint8array from invalid hex string: "${hexString}"`
    );
  }

  const buffer = new Uint8Array(
    hexString!.match(/../g)!.map((h: string) => parseInt(h, 16))
  );

  if (!length) {
    return buffer;
  }
  if (hexString.length / 2 > length) {
    throw new Error(
      "hex value cannot fit in a buffer of " + length + " byte(s)"
    );
  }

  // If a length is specified, ensure we sufficiently pad
  let paddedBuffer = new Uint8Array(length);
  paddedBuffer.set(buffer, length - buffer.length);
  return paddedBuffer;
};

function stringToBase64urlString(input: string): string {
  // string to base64 -- we do not rely on the browser's btoa since it's not present in React Native environments
  const base64String = btoa(input);
  return base64StringToBase64UrlEncodedString(base64String);
}

function hexStringToBase64url(input: string, length?: number): string {
  // Add an extra 0 to the start of the string to get a valid hex string (even length)
  // (e.g. 0x0123 instead of 0x123)
  const hexString = input.padStart(Math.ceil(input.length / 2) * 2, "0");
  const buffer = uint8ArrayFromHexString(hexString, length);

  return stringToBase64urlString(
    buffer.reduce((result, x) => result + String.fromCharCode(x), "")
  );
}

function convertTurnkeyApiKeyToJwk(input: {
  uncompressedPrivateKeyHex: string;
  compressedPublicKeyHex: string;
}): JsonWebKey {
  const { uncompressedPrivateKeyHex, compressedPublicKeyHex } = input;

  let jwk;
  try {
    jwk = pointDecode(uint8ArrayFromHexString(compressedPublicKeyHex));
  } catch (e) {
    throw new Error(
      `unable to load API key: invalid public key. Did you switch your public and private key?`
    );
  }

  // Ensure that d is sufficiently padded
  jwk.d = hexStringToBase64url(
    uncompressedPrivateKeyHex,
    DEFAULT_JWK_MEMBER_BYTE_LENGTH
  );

  return jwk;
}

// Example usage
const jsonBody = JSON.stringify({ example: "data" });
const publicKey = "yourCompressedPublicKeyHere"; // 64 bytes hex string
const privateKey = "yourUncompressedPrivateKeyHere"; // 64 bytes hex string

generateApiKeyStamp(jsonBody, publicKey, privateKey);
