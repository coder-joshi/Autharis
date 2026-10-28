export function isUniqueViolation(err: unknown, constraint?: string): boolean {
  type PgLike = { code?: string; constraint?: string; cause?: unknown } | null | undefined;
  const top = err as PgLike;
  const inner = top?.cause as PgLike;
  return [top, inner].some(
    (e) => e?.code === "23505" && (!constraint || e.constraint === constraint),
  );
}
