import { errorMessageOr } from "@/lib/utils/error";
import { logger } from "@/lib/logger";
import { createProvider } from "@/actions/provider";
import { getAuth } from "@/lib/auth/auth-server";
import { GITHUB_API_VERSION } from "@/lib/constant";
import { createAppAuth } from "@octokit/auth-app";
import { NextRequest, NextResponse } from "next/server";
import { App, Octokit } from "octokit";

// GitHub returns these for expiring-token apps; octokit's types omit them.
type TExpiringTokenFields = {
  refreshToken?: string;
  expiresAt?: string;
  refreshTokenExpiresAt?: string;
};

type TGitHubAppInstallation = {
  type: "token";
  tokenType: "installation";
  token: string;
  installationId: number;
  permissions: {
    actions: "write";
    administration: "write";
    attestations: "write";
    checks: "write";
    codespaces: "write";
    codespaces_lifecycle_admin: "write";
    contents: "write";
    metadata: "read";
    pull_requests: "write";
    repository_advisories: "write";
    repository_custom_properties: "write";
    security_events: "write";
    statuses: "write";
  };
  createdAt: string; // ISO timestamp
  expiresAt: string; // ISO timestamp
  repositorySelection: "all" | "selected";
};

export type TGitHubAppOAuthAuthentication = {
  type: "token";
  tokenType: "oauth";
  clientType: "github-app";
  clientId: string;
  clientSecret: string;
  token: string;
  refreshToken: string;
  expiresAt: string;
  refreshTokenExpiresAt: string; // ISO date string
};

async function handler(request: NextRequest) {
  try {
    const session = await getAuth(request);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const code = searchParams.get("code");
    const requestedInstallationId = searchParams.get("installation_id");

    if (!code) {
      return NextResponse.json({ error: "Missing code" }, { status: 400 });
    }
    if (requestedInstallationId && !/^\\d+$/.test(requestedInstallationId)) {
      return NextResponse.json(
        { error: "Invalid installation_id" },
        { status: 400 },
      );
    }

    const app = new App({
      oauth: {
        clientId: process.env.GITHUB_APP_CLIENT_ID!,
        clientSecret: process.env.GITHUB_APP_CLIENT_SECRET!,
      },
      appId: process.env.GITHUB_APP_ID!,
      privateKey: process.env.GITHUB_APP_PRIVATE_KEY!,
    });

    // Exchange the OAuth code FIRST: the resulting user token is what proves
    // who is calling, and it gates the installation token below.
    const token = await app.oauth.createToken({
      code,
    });

    // An OAuth callback for an already-installed GitHub App may omit
    // installation_id. Resolve it from installations visible to this user.
    const userOctokit = new Octokit({
      auth: token.authentication.token,
      request: { headers: { "X-GitHub-Api-Version": GITHUB_API_VERSION } },
    });

    const userInstallations = await userOctokit.paginate(
      "GET /user/installations",
      { per_page: 100 },
    );

    // Never accept an installation belonging to another GitHub App, even if
    // the user can access it. App IDs are numeric, so normalize both sides.
    const matchingInstallations = userInstallations.filter(
      (candidate) => String(candidate.app_id) === process.env.GITHUB_APP_ID,
    );
    const selectedInstallation = requestedInstallationId
      ? matchingInstallations.find(
          (candidate) => String(candidate.id) === requestedInstallationId,
        )
      : matchingInstallations.length === 1
        ? matchingInstallations[0]
        : undefined;

    if (!selectedInstallation) {
      return NextResponse.json(
        {
          error: matchingInstallations.length > 1 && !requestedInstallationId
            ? "Multiple GitHub App installations found; installation_id is required"
            : "No accessible installation found for this GitHub App",
        },
        { status: 400 },
      );
    }

    const installationId = String(selectedInstallation.id);
    const octokit: Octokit = new Octokit({
      authStrategy: createAppAuth,
      version: GITHUB_API_VERSION,
      auth: {
        appId: process.env.GITHUB_APP_ID!,
        privateKey: process.env.GITHUB_APP_PRIVATE_KEY!,
        installationId,
      },
      request: {
        headers: { "X-GitHub-Api-Version": GITHUB_API_VERSION },
      },
    });

    const installation = (await octokit.auth({
      type: "installation",
    })) as TGitHubAppInstallation;

    const auth = token.authentication as typeof token.authentication &
      TExpiringTokenFields;

    await createProvider({
      provider: "Github",
      access_token: auth.token,
      refresh_token: auth.refreshToken || "", // Pass refreshToken if available
      access_token_expires_at: auth.expiresAt
        ? new Date(auth.expiresAt).getTime()
        : Date.now() + 28800000, // Default to 8h if missing
      refresh_token_expires_at: auth.refreshTokenExpiresAt
        ? new Date(auth.refreshTokenExpiresAt).getTime()
        : undefined,
      token_type: installation.tokenType,
      installation_access_token: installation.token,
      user_id: "",
    });

    return NextResponse.json({
      success: true,
      message: "GitHub authentication successful",
    });
  } catch (error) {
    logger.error("Error in GitHub authentication handler:", error);
    return NextResponse.json(
      {
        error: errorMessageOr(error, "An unexpected error occurred"),
      },
      { status: 500 },
    );
  }
}

export { handler as GET, handler as POST };
