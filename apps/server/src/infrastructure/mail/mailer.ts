import { env } from "../../config/env.js";
export interface Mailer {
  sendVerification(to: string, link: string): Promise<void>;
  sendPasswordReset(to: string, link: string): Promise<void>;
  sendAlreadyRegistered(to: string): Promise<void>;
}
export class ConsoleMailer implements Mailer {
  async sendVerification(to: string, link: string) {
    console.log(`[mail] verify ${to}: ${link}`);
  }
  async sendPasswordReset(to: string, link: string) {
    console.log(`[mail] reset ${to}: ${link}`);
  }
  async sendAlreadyRegistered(to: string) {
    console.log(`[mail] ${to} tried to register but already has an account`);
  }
}
let current: Mailer | undefined;
export function getMailer(): Mailer {
  if (!current) {
    if (env.NODE_ENV === "production") {
      throw new Error(
        "No mailer configured. Call setMailer() with a realprovider before production.",
      );
    }
    current = new ConsoleMailer();
  }
  return current;
}
export function setMailer(mailer: Mailer): void {
  current = mailer;
}
