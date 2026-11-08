import type { AuthState } from "../modules/sessions/session.service.js";
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth?: AuthState;
    }
  }
}
export {};
