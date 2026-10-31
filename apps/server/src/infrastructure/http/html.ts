import type { Response } from "express";
export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}
export const csrfField = (token: string) =>
  `<input type="hidden" name="_csrf" value="${escapeHtml(token)}">`;
/** Origin (or scheme) of a redirect URI, for the CSP form-action list. */
export function formActionSource(uri: string): string {
  const u = new URL(uri);
  return u.protocol === "http:" || u.protocol === "https:" ? u.origin : u.protocol;
}
export function renderPage(
  res: Response,
  opts: { title: string; body: string; status?: number; formActionOrigins?: string[] },
): void {
  const csp = [
    "default-src 'none'",
    "style-src 'self'",
    "img-src 'self' data:",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    ["form-action 'self'", ...(opts.formActionOrigins ?? [])].join(" "),
  ].join("; ");
  res.status(opts.status ?? 200);
  res.setHeader("Content-Security-Policy", csp);
  res.setHeader("Cache-Control", "no-store");
  res
    .type("html")
    .send(
      `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
        `<meta name="viewport" content="width=device-width, initial-scale=1">` +
        `<title>${escapeHtml(opts.title)} · Autharis</title>` +
        `<link rel="stylesheet" href="/assets/auth.css"></head>` +
        `<body><main>${opts.body}</main></body></html>`,
    );
}
