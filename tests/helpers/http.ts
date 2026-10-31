import type { Agent } from "supertest";

/** GETs a page and returns the CSRF value from its form. The agent keeps the cookie. */
export async function csrfFrom(agent: Agent, path: string): Promise<string> {
  const res = await agent.get(path);
  const match = /name="_csrf" value="([^"]+)"/.exec(res.text);
  if (!match) throw new Error(`no csrf field on ${path}`);
  return match[1]!;
}
