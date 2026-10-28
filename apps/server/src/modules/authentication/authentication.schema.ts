import { z } from "zod";
import { displayNameField, emailField } from "../identity/user.validation.js";
export const passwordField = z.string().min(12).max(128);
export const registerSchema = z.object({
  email: emailField,
  password: passwordField,
  displayName: z.preprocess((v) => (v === "" ? undefined : v), displayNameField.optional()),
});
export const emailOnlySchema = z.object({ email: emailField });
export const tokenSchema = z.object({ token: z.string().min(20).max(200) });
export const resetSchema = z.object({
  token: z.string().min(20).max(200),
  password: passwordField,
});
export const loginSchema = z.object({
  email: z.string().max(254),
  password: z.string().min(1).max(128),
});
