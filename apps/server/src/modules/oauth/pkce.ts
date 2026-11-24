import { safeEqual, sha256Base64Url } from "../../infrastructure/cryptography/tokens.js";

const VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;

export function verifyPkceS256(verifier: string, storedChallenge: string): boolean {
  return VERIFIER.test(verifier) && safeEqual(sha256Base64Url(verifier), storedChallenge);
}
