import { createHmac, timingSafeEqual } from "node:crypto";

const SIGNED_DOWNLOAD_TTL_SECONDS = 5 * 60;

export function createSignedDownloadPath(
  signingKey: Buffer,
  fileId: number,
  nowSeconds: number = currentUnixTime(),
): string {
  const expires = nowSeconds + SIGNED_DOWNLOAD_TTL_SECONDS;
  const signature = signDownload(signingKey, fileId, expires);
  return `/files/${fileId}/signed-download?expires=${expires}&signature=${signature}`;
}

export function verifySignedDownload(
  _signingKey: Buffer,
  _fileId: number,
  expiresValue: string,
  signature: string,
  nowSeconds: number = currentUnixTime(),
): boolean {
  const signBuff = Buffer.from(signature);
  const expires = parseInt(expiresValue);

  if (expires <= nowSeconds) {
    return false;
  }

  const ogSignBuff = Buffer.from(signDownload(_signingKey, _fileId, expires));

  try {
    return timingSafeEqual(signBuff, ogSignBuff);
  } catch {
    return false;
  }
}

function signDownload(
  _signingKey: Buffer,
  _fileId: number,
  _expires: number,
): string {
  const payload = `GET\n/files/${_fileId}/signed-download\n${_expires}`;
  return createHmac("sha256", _signingKey).update(payload).digest("hex");
}

function currentUnixTime(): number {
  return Math.floor(Date.now() / 1000);
}
