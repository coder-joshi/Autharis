import type { Mailer } from "../../apps/server/src/infrastructure/mail/mailer.js";
export class InMemoryMailer implements Mailer {
  sent: { kind: "verify" | "reset" | "duplicate"; to: string; link?: string }[] = [];
  async sendVerification(to: string, link: string) {
    this.sent.push({ kind: "verify", to, link });
  }
  async sendPasswordReset(to: string, link: string) {
    this.sent.push({ kind: "reset", to, link });
  }
  async sendAlreadyRegistered(to: string) {
    this.sent.push({ kind: "duplicate", to });
  }
  tokenOf(kind: "verify" | "reset"): string {
    const entry = [...this.sent].reverse().find((m) => m.kind === kind);
    return new URL(entry!.link!).searchParams.get("token")!;
  }
}
