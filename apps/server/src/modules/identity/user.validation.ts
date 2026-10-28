import { z } from "zod";
export function normalizeEmail(email: string): string {
return email.normalize("NFKC").trim().toLowerCase();
}
export const emailField = z.string().trim().min(3).max(254).email();
export const displayNameField = z.string().trim().min(1).max(100);