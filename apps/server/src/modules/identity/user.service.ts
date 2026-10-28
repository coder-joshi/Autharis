import { db, type DbOrTx } from "../../infrastructure/database/db.js";
import { isUniqueViolation } from "../../infrastructure/database/error.js";
import { normalizeEmail } from "./user.validation.js";
import { userRepository, type UserRow } from "./user.repository.js";
export class EmailAlreadyRegisteredError extends Error {
  constructor() {
    super("email already registered");
  }
}
export interface CreateUserInput {
  email: string;
  displayName?: string;
  passwordHash?: string | null;
  role?: "user" | "admin";
  emailVerified?: boolean;
}

export const userService = {
  async create(input: CreateUserInput, tx: DbOrTx = db): Promise<UserRow> {
    const email = input.email.trim();
    try {
      return await userRepository.insert(
        {
          email,
          emailNormalized: normalizeEmail(email),
          displayName: input.displayName ?? null,
          passwordHash: input.passwordHash ?? null,
          role: input.role ?? "user",
          emailVerifiedAt: input.emailVerified ? new Date() : null,
        },
        tx,
      );
    } catch (err) {
      if (isUniqueViolation(err)) throw new EmailAlreadyRegisteredError();
      throw err;
    }
  },
  findById: (id: string) => userRepository.findById(id),
  findByEmail: (email: string) => userRepository.findByEmailNormalized(normalizeEmail(email)),
  markEmailVerified: (id: string) => userRepository.markEmailVerified(id),
  setPasswordHash: (id: string, hash: string) => userRepository.setPasswordHash(id, hash),
  /** Revocation of sessions and tokens is added in Steps 10 and 16. */
  disable: (id: string) => userRepository.setStatus(id, "disabled"),
  enable: (id: string) => userRepository.setStatus(id, "active"),
};
/** The only shape of a user that may leave the service layer toward HTTP. */
export function toSafeUser(user: UserRow) {
  return {
    id: user.id,
    email: user.email,
    emailVerified: user.emailVerifiedAt !== null,
    displayName: user.displayName,
    status: user.status,
    role: user.role,
    createdAt: user.createdAt,
  };
}
