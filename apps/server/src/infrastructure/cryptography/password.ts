import { hash, verify } from "@node-rs/argon2";
import { randomToken } from "./tokens.js";
// Argon2id is the library default. These are the OWASP minimum parameters.
const OPTIONS = { memoryCost: 19456, timeCost: 2, parallelism: 1 } as const;
function normalize(password: string): string {
  return password.normalize("NFKC");
}
export function hashPassword(password: string): Promise<string> {
  return hash(normalize(password), OPTIONS);
}
/** Never throws: a malformed or foreign hash simply fails verification. */
export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  try {
    return await verify(storedHash, normalize(password), OPTIONS);
  } catch {
    return false;
  }
}
let dummy: Promise<string> | undefined;
/** A real hash of a random value, verified when the user does not exist so
timing matches. */
export function dummyHash(): Promise<string> {
  dummy ??= hashPassword(randomToken(16));
  return dummy;
}
