import type {
  ErrorRequestHandler
} from "express";

export const errorHandler: ErrorRequestHandler = (
  err,
  _req,
  res,
  _next
) => {
  console.error("Request failed", err);

  res.status(500).json({
    error: "internal_server_error"
  });
};