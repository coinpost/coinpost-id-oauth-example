import { generateCodeVerifier, generateState } from "arctic";
import { cookies } from "next/headers";
import { coinpost } from "../../../lib/auth";

export async function GET(): Promise<Response> {
  const state = generateState();
  const codeVerifier = generateCodeVerifier();
  const url = await coinpost.createAuthorizationURL(state, codeVerifier, {
    scopes: ["user.public"],
  });

  cookies().set("coinpost_oauth_state", state, {
    path: "/",
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    maxAge: 60 * 10,
    sameSite: "lax",
  });

  cookies().set("coinpost_code_verifier", codeVerifier, {
    path: "/",
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    maxAge: 60 * 10,
    sameSite: "lax",
  });

  return Response.redirect(url);
}
