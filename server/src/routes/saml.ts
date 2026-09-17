import { Router } from "express";
import passport from "passport";
import { Strategy, Profile } from "@node-saml/passport-saml";
import crypto from "crypto";
import { eq, and } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import { authUsers, authAccounts, authSessions } from "@paperclipai/db";
import { loadConfig } from "../config.js";
import { deriveAuthCookiePrefix, shouldDisableSecureAuthCookies } from "../auth/better-auth.js";

// Creamos un singleton para la estrategia
let samlStrategyInstance: Strategy | null = null;

function buildSamlStrategy(config: ReturnType<typeof loadConfig>): Strategy {
  if (samlStrategyInstance) return samlStrategyInstance;

  samlStrategyInstance = new Strategy(
    {
      entryPoint: config.samlIdpEntryPoint || "",
      issuer: config.samlSpEntityId || "",
      callbackUrl: config.samlSpAcsUrl || "",
      idpCert: config.samlIdpCert || "",
      logoutUrl: config.samlIdpSloUrl || "",
      logoutCallbackUrl: config.samlSpSloUrl || "",
      identifierFormat: null,
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: false,
    },
    (profile: Profile | null | undefined, done: (err: Error | null, user?: any) => void) => {
      if (!profile) {
        return done(new Error("No profile returned from SAML"));
      }
      return done(null, profile);
    },
    (profile: any, done: any) => {
      return done(null, profile);
    }
  );

  return samlStrategyInstance;
}

export function samlRoutes(db: Db): Router {
  const router = Router();
  const config = loadConfig();
  const strategy = buildSamlStrategy(config);

  passport.use("saml-admin", strategy as any);

  // 1. Iniciar sesión: SP-Initiated
  router.get(
    "/saml/login",
    passport.authenticate("saml-admin", {
      session: false,
      failureRedirect: "/?error=saml_init",
    })
  );

  // 2. Callback de SAML (ACS)
  router.post(
    "/saml/callback",
    passport.authenticate("saml-admin", {
      session: false,
      failureRedirect: "/?error=saml_callback",
    }),
    async (req, res) => {
      try {
        const profile = req.user as any;
        const email = profile.emailaddress || profile["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"] || profile.email;
        let name = profile.displayname || profile["http://schemas.microsoft.com/identity/claims/displayname"] || profile.name || email;
        const nameID = profile.nameID || profile.nameId;
        const sessionIndex = profile.sessionIndex;

        if (!email) {
          throw new Error("SAML Assertion does not contain an email");
        }

        // Buscar el usuario por email
        let users = await db.select().from(authUsers).where(eq(authUsers.email, email)).limit(1);
        let user = users[0];

        const now = new Date();

        if (!user) {
          // Autoprovisionamiento
          const userId = crypto.randomUUID();
          user = (await db.insert(authUsers).values({
            id: userId,
            email,
            name,
            createdAt: now,
            updatedAt: now,
            emailVerified: true,
          }).returning())[0];
        }

        // Buscar cuenta vinculada
        let accounts = await db.select().from(authAccounts).where(
          and(eq(authAccounts.userId, user.id), eq(authAccounts.providerId, "saml_azure"))
        ).limit(1);

        if (accounts.length === 0) {
          await db.insert(authAccounts).values({
            id: crypto.randomUUID(),
            userId: user.id,
            providerId: "saml_azure",
            accountId: nameID || email, // Usamos nameID para SLO
            accessToken: sessionIndex || null, // Guardamos el sessionIndex para SLO
            createdAt: now,
            updatedAt: now,
          });
        } else if (sessionIndex && accounts[0].accessToken !== sessionIndex) {
          // Actualizamos el sessionIndex si cambió
          await db.update(authAccounts)
            .set({ accessToken: sessionIndex, updatedAt: now })
            .where(eq(authAccounts.id, accounts[0].id));
        }

        // Crear sesión de Better Auth
        const sessionId = crypto.randomUUID();
        const sessionToken = crypto.randomUUID(); // Better Auth token format
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7); // 7 días de sesión

        await db.insert(authSessions).values({
          id: sessionId,
          userId: user.id,
          token: sessionToken,
          expiresAt,
          createdAt: now,
          updatedAt: now,
          ipAddress: req.ip || null,
          userAgent: req.headers["user-agent"] || null,
        });

        // Configurar cookie de Better Auth
        const cookiePrefix = deriveAuthCookiePrefix();
        const disableSecureCookies = shouldDisableSecureAuthCookies({
          deploymentMode: config.deploymentMode,
          deploymentExposure: config.deploymentExposure,
          authBaseUrlMode: config.authBaseUrlMode,
          authPublicBaseUrl: config.authPublicBaseUrl,
          publicUrl: config.authPublicBaseUrl,
        });

        const cookieName = disableSecureCookies ? `${cookiePrefix}.session_token` : `__Secure-${cookiePrefix}.session_token`;
        
        res.cookie(cookieName, sessionToken, {
          httpOnly: true,
          secure: !disableSecureCookies,
          sameSite: "lax",
          path: "/",
          expires: expiresAt,
        });

        // Redirigir a la UI (Home)
        res.redirect("/");
      } catch (error) {
        console.error("SAML Callback Error:", error);
        res.redirect("/?error=saml_processing");
      }
    }
  );

  // 3. Metadata XML
  router.get("/saml/metadata", (req, res) => {
    res.type("application/xml");
    res.status(200).send(strategy.generateServiceProviderMetadata(null as any));
  });

  // 4. Single Logout (SLO)
  router.get("/saml/logout", async (req, res) => {
    const cookiePrefix = deriveAuthCookiePrefix();
    const disableSecureCookies = shouldDisableSecureAuthCookies({
      deploymentMode: config.deploymentMode,
      deploymentExposure: config.deploymentExposure,
      authBaseUrlMode: config.authBaseUrlMode,
      authPublicBaseUrl: config.authPublicBaseUrl,
    });
    
    const cookieName = disableSecureCookies ? `${cookiePrefix}.session_token` : `__Secure-${cookiePrefix}.session_token`;
    const sessionToken = req.cookies[cookieName];

    let isSso = false;
    if (sessionToken) {
      const sessions = await db.select().from(authSessions).where(eq(authSessions.token, sessionToken));
      if (sessions.length > 0) {
        const accounts = await db.select().from(authAccounts).where(
          and(eq(authAccounts.userId, sessions[0].userId), eq(authAccounts.providerId, "saml_azure"))
        );
        if (accounts.length > 0) {
          isSso = true;
        }
      }
      await db.delete(authSessions).where(eq(authSessions.token, sessionToken));
    }

    res.clearCookie(cookieName, { path: "/" });

    if (isSso && config.samlIdpSloUrl) {
      res.redirect(config.samlIdpSloUrl);
    } else {
      res.redirect("/");
    }
  });

  router.post("/saml/slo", (req, res) => {
    res.redirect("/");
  });

  return router;
}
