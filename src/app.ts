import { AppRoutes } from "./presentation/routes";
import { Server } from "./presentation/server";
import { envs } from "./config/envs";
import { CredoAgentBuilder } from "./infrastructure/agent/credo-agent.builder";
import { OpenId4VcModule } from "@credo-ts/openid4vc";
import { Agent, W3cV2Credential } from "@credo-ts/core";
import { CredentialsService } from "./presentation/issuer/services/credentials.service";
import { WellKnownService } from "./presentation/issuer/services/well-known.service";

async function main() {
  const agentBuilder = new CredoAgentBuilder();
  const server = new Server({
    port: envs.PORT ?? 3000,
  });

  const app = server.getApp;

  app.use((req, res, next) => {
    console.log(`\n🕵️ [EXPRESS HTTP] ${req.method} ${req.url}`);
    next();
  });

  const agent = await agentBuilder
    .setConfiguration({
      allowInsecureHttpUrls: true,
      autoUpdateStorageOnStartup: true,
    })
    .setOpenId4VpModule({
      role: "issuer",
      openIdConfig: new OpenId4VcModule({
        app,
        issuer: {
          baseUrl: `${envs.DOMAIN}/issuer`,
          credentialRequestToCredentialMapper: async ({
            credentialConfigurationId,
            holderBinding,
            issuanceSession,
          }) => {
            console.log(
              "\n======================================================",
            );
            console.log("🔥 [APP] CREDENTIAL MAPPER CALLED!");
            console.log(
              `- Request Configuration ID: ${credentialConfigurationId}`,
            );
            console.log(`- Holder Binding: ${JSON.stringify(holderBinding)}`);
            console.log(
              "======================================================\n",
            );

            const did = `did:web:${envs.DOMAIN.replace(/^https?:\/\//, "")}`;

            // Build holder binding for the credential
            const holderKey = holderBinding.keys[0];
            const holder =
              holderKey!.method === "did"
                ? { method: "did" as const, didUrl: holderKey!.didUrl }
                : { method: "jwk" as const, jwk: holderKey!.jwk };

            if (credentialConfigurationId === "vc_jwt") {
              return {
                type: "credentials",
                format: "vc+sd-jwt",
                credentials: [
                  {
                    alg: "EdDSA",
                    verificationMethod: `${did}#owner`,
                    credential: new W3cV2Credential({
                      type: ["VerifiableCredential", "MyCredentialType"],
                      issuer: did,
                      credentialSubject: {
                        given_name: "Juan",
                        family_name: "Pérez",
                        birth_date: "1990-01-15",
                        document_number: "12345678",
                      },
                    }),
                    holder,
                    disclosureFrame: {
                      _sd: [
                        "given_name",
                        "family_name",
                        "birth_date",
                        "document_number",
                      ],
                    },
                  },
                ],
              };
            }

            throw new Error(
              `Unsupported credential configuration: ${credentialConfigurationId}`,
            );
          },
        },
      }),
    })
    .build();

  // Ensure the issuer record exists before serving requests
  const credentialsService = new CredentialsService(agent);
  await credentialsService.ensureIssuerExists();

  // Pre-register the DID document in the DB so Credo can find it when signing credentials
  const wellKnownService = new WellKnownService(agent);
  await wellKnownService.getDidDocument();
  console.log("✅ DID Document pre-registered in DB");

  server.setRoutes(AppRoutes.routes(agent));
  server.start();
}

main().catch((error) => {
  console.error("Fatal error during startup:", error);
  process.exit(1);
});
