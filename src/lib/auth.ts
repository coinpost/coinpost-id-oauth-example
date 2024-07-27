import { BetterSqlite3Adapter } from "@lucia-auth/adapter-sqlite";
import { OAuth2ProviderWithPKCE } from "arctic";
import type { Session, User } from "lucia";
import { Lucia } from "lucia";
import { cookies } from "next/headers";
import { createDate, TimeSpan } from "oslo";
import { OAuth2Client } from "oslo/oauth2";
import { cache } from "react";
import type { DatabaseUser } from "./db";
import { db } from "./db";

const adapter = new BetterSqlite3Adapter(db, {
  user: "user",
  session: "session",
});

export const lucia = new Lucia(adapter, {
  sessionCookie: {
    attributes: {
      secure: process.env.NODE_ENV === "production",
    },
  },
  getUserAttributes: (attributes) => {
    return {
      coinpostId: attributes.coinpost_id,
      username: attributes.username,
    };
  },
});

declare module "lucia" {
  interface Register {
    Lucia: typeof lucia;
    DatabaseUserAttributes: Omit<DatabaseUser, "id">;
  }
}

export const validateRequest = cache(
  async (): Promise<
    { user: User; session: Session } | { user: null; session: null }
  > => {
    const sessionId = cookies().get(lucia.sessionCookieName)?.value ?? null;
    if (!sessionId) {
      return {
        user: null,
        session: null,
      };
    }

    const result = await lucia.validateSession(sessionId);
    // next.js throws when you attempt to set cookie when rendering page
    try {
      if (result.session && result.session.fresh) {
        const sessionCookie = lucia.createSessionCookie(result.session.id);
        cookies().set(
          sessionCookie.name,
          sessionCookie.value,
          sessionCookie.attributes
        );
      }
      if (!result.session) {
        const sessionCookie = lucia.createBlankSessionCookie();
        cookies().set(
          sessionCookie.name,
          sessionCookie.value,
          sessionCookie.attributes
        );
      }
    } catch {}
    return result;
  }
);

export class CoinPost implements OAuth2ProviderWithPKCE {
  private client: OAuth2Client;
  private clientSecret: string;

  constructor(
    clientId: string,
    clientSecret: string,
    options?: {
      redirectURI?: string;
    }
  ) {
    const baseUrl = "https://id.coinpost.dev";

    const authorizeEndpoint = baseUrl + "/web/oauth/authorize";
    const tokenEndpoint = baseUrl + "/oauth/token";

    this.client = new OAuth2Client(clientId, authorizeEndpoint, tokenEndpoint, {
      redirectURI: options?.redirectURI,
    });
    this.clientSecret = clientSecret;
  }

  public async createAuthorizationURL(
    state: string,
    codeVerifier: string,
    options?: {
      scopes?: string[];
    }
  ): Promise<URL> {
    return await this.client.createAuthorizationURL({
      state,
      codeVerifier,
      scopes: options?.scopes ?? [],
      codeChallengeMethod: "plain",
    });
  }

  public async validateAuthorizationCode(
    code: string,
    codeVerifier: string
  ): Promise<CoinPostTokens> {
    const result =
      await this.client.validateAuthorizationCode<AuthorizationCodeResponseBody>(
        code,
        {
          credentials: this.clientSecret,
          codeVerifier,
        }
      );
    const tokens: CoinPostTokens = {
      accessToken: result.access_token,
      refreshToken: result.refresh_token,
      accessTokenExpiresAt: createDate(new TimeSpan(result.expires_in, "s")),
    };
    return tokens;
  }
}

interface AuthorizationCodeResponseBody {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

export interface CoinPostTokens {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: Date;
}

export const coinpost = new CoinPost(
  process.env.COINPOST_CLIENT_ID!,
  process.env.COINPOST_CLIENT_SECRET!,
  {
    redirectURI: "http://localhost:3000/login/coinpost/callback",
  }
);
