import { OAuth2RequestError } from "arctic";
import { generateId } from "lucia";
import { cookies } from "next/headers";
import { coinpost, lucia } from "~/lib/auth";
import type { DatabaseUser } from "~/lib/db";
import { db } from "~/lib/db";

export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const storedState = cookies().get("coinpost_oauth_state")?.value ?? null;
  if (!code || !state || !storedState || state !== storedState) {
    return new Response(null, {
      status: 400,
    });
  }

  const storedCodeVerifier =
    cookies().get("coinpost_code_verifier")?.value ?? null;
  if (!storedCodeVerifier) {
    return new Response(null, {
      status: 400,
    });
  }

  try {
    const tokens = await coinpost.validateAuthorizationCode(
      code,
      storedCodeVerifier
    );
    const coinpostUserResponse = await fetch(
      `https://id.coinpost.dev/users/me`,
      {
        headers: {
          Authorization: `Bearer ${tokens.accessToken}`,
        },
      }
    );
    const coinpostUser: CoinPostUser = await coinpostUserResponse.json();
    const existingUser = db
      .prepare("SELECT * FROM user WHERE coinpost_id = ?")
      .get(coinpostUser.data.id) as DatabaseUser | undefined;

    if (existingUser) {
      const session = await lucia.createSession(existingUser.id, {});
      const sessionCookie = lucia.createSessionCookie(session.id);
      cookies().set(
        sessionCookie.name,
        sessionCookie.value,
        sessionCookie.attributes
      );
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/",
        },
      });
    }

    const userId = generateId(15);
    db.prepare(
      "INSERT INTO user (id, coinpost_id, username) VALUES (?, ?, ?)"
    ).run(userId, coinpostUser.data.id, coinpostUser.data.name);
    const session = await lucia.createSession(userId, {});
    const sessionCookie = lucia.createSessionCookie(session.id);
    cookies().set(
      sessionCookie.name,
      sessionCookie.value,
      sessionCookie.attributes
    );
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/",
      },
    });
  } catch (e) {
    if (
      e instanceof OAuth2RequestError &&
      e.message === "bad_verification_code"
    ) {
      // invalid code
      return new Response(null, {
        status: 400,
      });
    }
    return new Response(null, {
      status: 500,
    });
  }
}

interface CoinPostUser {
  data: {
    id: string;
    name: string;
    bio: string;
    tagline: string;
    avatar_image_url: string;
    email: string;
    lang: string;
    status: number;
    created_at: string;
  };
}
