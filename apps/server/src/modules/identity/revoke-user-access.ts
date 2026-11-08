import { sessionService } from "../sessions/session.service.js";

/** Step 16 adds access and refresh token revocation to this function. */
export async function revokeAllUserAccess(userId: string): Promise<void> {
  await sessionService.revokeAllForUser(userId);
}
