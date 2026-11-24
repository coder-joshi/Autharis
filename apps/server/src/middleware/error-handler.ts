import type { ErrorRequestHandler } from "express";

export const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
  const status = typeof err?.status === "number" ? err.status : 500;
  if (status >= 400 && status < 500) {
    res.status(status).json({ error: "invalid_request" });
    return;
  }
  console.error("Request failed", err);

  res.status(500).json({
    error: "server_error",
  });
};
