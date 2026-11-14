import type { RequestHandler } from "express";
import { sendErrorPage } from "./errors.ts";
import { timingSafeEqual } from "node:crypto";

export function validateRequestOrigin(_appOrigin: string): RequestHandler {
  return (_req, _res, next) => {
    if (_req.method !== "POST") {
      return next();
    }

    const reqOrigin = _req.headers.origin || _req.headers.referer || "";

    if (!URL.canParse(reqOrigin) || new URL(reqOrigin).origin !== _appOrigin) {
      return sendErrorPage(
        _res,
        403,
        "Forbidden",
        "Request not coming from app",
      );
    }
    next();
  };
}

export function csrfTokensMatch(_expected: string, _actual: unknown): boolean {
  try {
    if (typeof _actual !== "string") {
      throw new Error();
    }
    if (timingSafeEqual(Buffer.from(_actual), Buffer.from(_expected))) {
      return true;
    }
  } catch {
    return false;
  }
  return false;
}
