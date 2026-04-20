import { Agent } from "@credo-ts/core";
import { OpenId4VcApi } from "@credo-ts/openid4vc";
import * as crypto from "crypto";

const ISSUER_ID = "oid4vci_v5";

export class CredentialsService {
  constructor(private readonly agent: Agent) {}

  /**
   * Ensures the issuer record exists in the database.
   * Should be called once at startup.
   */
  public async ensureIssuerExists() {
    const openId4VcModule = this.agent.modules.openid4vc as OpenId4VcApi;

    // Check if issuer already exists
    try {
      const existing =
        await openId4VcModule.issuer?.getIssuerByIssuerId(ISSUER_ID);
      if (existing) {
        console.log(`Issuer "${ISSUER_ID}" already exists, skipping creation.`);
        return existing;
      }
    } catch {
      // Issuer not found, proceed to create
    }

    const issuer = await openId4VcModule.issuer?.createIssuer({
      issuerId: ISSUER_ID,
      display: [
        {
          name: "GCBA",
          description: "Gobierno de la Ciudad de Buenos Aires",
          text_color: "#000000",
          background_color: "#FFFFFF",
          logo: {
            url: "https://www.camoca.com.ar/wp-content/uploads/2014/10/logo-gcba.jpg",
            alt_text: "GCBA logo",
          },
        },
      ],
      credentialConfigurationsSupported: {
        vc_jwt: {
          format: "vc+sd-jwt",
          scope: "MyCredentialScope",
          cryptographic_binding_methods_supported: [
            "did:web",
            "did:key",
            "did:jwk",
            "jwk",
          ],
          cryptographic_suites_supported: ["EdDSA", "ES256", "ES256K"],
          proof_types_supported: {
            jwt: {
              proof_signing_alg_values_supported: ["EdDSA", "ES256", "ES256K"],
            },
          },
          display: [
            {
              name: "Credencial Ciudadana",
              locale: "es-AR",
              background_color: "#004a99",
              text_color: "#ffffff",
            },
          ],
          credential_definition: {
            type: ["VerifiableCredential", "MyCredentialType"],
            credentialSubject: {
              given_name: { mandatory: true, display: [{ name: "Nombre" }] },
              family_name: { mandatory: true, display: [{ name: "Apellido" }] },
              birth_date: {
                mandatory: true,
                display: [{ name: "Fecha de Nacimiento" }],
              },
              document_number: {
                mandatory: true,
                display: [{ name: "Documento" }],
              },
            },
          },
        },
      },
    });

    console.log(`Issuer "${ISSUER_ID}" created successfully.`);
    return issuer;
  }

  public async createCredentialOffer() {
    const openId4VcModule = this.agent.modules.openid4vc as OpenId4VcApi;

    const result = await openId4VcModule.issuer?.createCredentialOffer({
      issuerId: ISSUER_ID,
      credentialConfigurationIds: ["vc_jwt"],
      preAuthorizedCodeFlowConfig: {
        preAuthorizedCode: crypto.randomUUID(),
        txCode: {
          length: 6,
          charset: "numeric",
        },
      },
    });

    const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${result?.credentialOffer}`;

    console.log(`\n======================================================`);
    console.log(`💳 NUEVA OFERTA DE CREDENCIAL GENERADA`);
    console.log(`======================================================`);
    console.log(`🔗 Link de la Oferta: ${result?.credentialOffer}`);
    console.log(
      `📌 PIN generada para Paradym: ${result?.issuanceSession.userPin}`,
    );
    console.log(`======================================================\n`);

    return {
      credentialOffer: result?.credentialOffer,
      credentialOfferQr: qrCodeUrl,
      sessionId: result?.issuanceSession.id,
      pin: result?.issuanceSession.userPin,
    };
  }
}
