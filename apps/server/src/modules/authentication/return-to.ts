/** Only same-origin paths that start with /authorize? are accepted.
Everything else is ignored. */
export function safeReturnTo(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 4096) return null;
  if (!value.startsWith("/authorize?")) return null;
  for (const ch of value) {
    if (ch.charCodeAt(0) < 32 || ch === "\\") return null;
  }
  return value;
}
/** Removes one value from `prompt` so a finished login or consent step
cannot loop forever. */
export function stripPromptValue(returnTo: string, drop: "login" | "consent"): string {
  const url = new URL(returnTo, "http://placeholder.invalid");
  const current = url.searchParams.get("prompt");
  if (current !== null) {
    const rest = current.split(" ").filter((p) => p !== "" && p !== drop);
    if (rest.length > 0) url.searchParams.set("prompt", rest.join(" "));
    else url.searchParams.delete("prompt");
  }
  return url.pathname + url.search;
}
