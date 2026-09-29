import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { buildCsp, generateNonce, type CspEnv } from "./src/lib/csp";

/**
 * Per-request nonce-based Content-Security-Policy middleware.
 *
 * Generates a cryptographically random nonce for every request, sets the
 * `Content-Security-Policy` header with `script-src 'self' 'nonce-…'
 * 'strict-dynamic'` (no `'unsafe-inline'`), and forwards the nonce to the
 * app via the `x-nonce` request header so Next.js can attach it to its
 * inline bootstrap scripts.
 *
 * Rollout: set `CSP_REPORT_ONLY=true` to emit
 * `Content-Security-Policy-Report-Only` instead of the enforcing header.
 * Violations are POSTed to `/api/csp-report`.
 */

function resolveEnv(): CspEnv {
  if (process.env.NODE_ENV === "development") return "development";
  if (process.env.VERCEL_ENV === "preview") return "preview";
  return "production";
}

export function middleware(request: NextRequest) {
  const nonce = generateNonce();
  const env = resolveEnv();
  const reportOnly = process.env.CSP_REPORT_ONLY === "true";

  const csp = buildCsp(env, {
    nonce,
    apiOrigin: process.env.NEXT_PUBLIC_API_URL,
    wsOrigin: process.env.NEXT_PUBLIC_WS_URL,
    reportUri: reportOnly ? "/api/csp-report" : undefined,
  });

  // Forward the nonce to the app via a request header so that Next.js can
  // read it (e.g. in layout.tsx) and attach it to inline scripts.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);

  const response = NextResponse.next({
    request: { headers: requestHeaders },
  });

  response.headers.set(
    reportOnly
      ? "Content-Security-Policy-Report-Only"
      : "Content-Security-Policy",
    csp
  );

  return response;
}

export const config = {
  // Exclude static assets, image optimization and the CSP report endpoint
  // itself from the middleware so we don't pay the nonce cost on every
  // asset request.
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|api/csp-report).*)",
  ],
};
