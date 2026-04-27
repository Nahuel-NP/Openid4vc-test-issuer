import { Agent } from "@credo-ts/core";
import { OpenId4VcApi } from "@credo-ts/openid4vc";
import * as crypto from "crypto";
import { ISSUER_ID } from "../../../config/constants/issuer.constants";


export class CredentialsService {
  constructor(private readonly agent: Agent) {}

  /**
   * Ensures the issuer record exists in the database.
   * Should be called once at startup.
   */
  public async ensureIssuerExists() {
    const openId4VcModule = this.agent.modules.openid4vc as OpenId4VcApi;

    const issuerConfig = {
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
        citizen_card: {
          format: "dc+sd-jwt" as const,
          vct: "MyCredentialType",
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
          claims: {
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
    };

    try {
      const existing = await openId4VcModule.issuer?.getIssuerByIssuerId(ISSUER_ID);
      if (existing) {
        console.log(`Issuer "${ISSUER_ID}" already exists, skipping creation.`);
        return existing;
      }
    } catch (e) {
      // Issuer not found or error, proceed to create
    }

    const issuer = await openId4VcModule.issuer?.createIssuer(issuerConfig);
    console.log(`Issuer "${ISSUER_ID}" created successfully.`);
    return issuer;
  }

  public async createCredentialOffer() {
    const openId4VcModule = this.agent.modules.openid4vc as OpenId4VcApi;

    const result = await openId4VcModule.issuer?.createCredentialOffer({
      issuerId: ISSUER_ID,
      credentialConfigurationIds: ["citizen_card"],
      preAuthorizedCodeFlowConfig: {
        preAuthorizedCode: crypto.randomUUID(),
        txCode: {
          length: 6,
          charset: "numeric",
        },
      },
    });

    console.log({result})
    const encodedOffer = encodeURIComponent(result?.credentialOffer ?? '');
    const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodedOffer}`;

  console.log({encodedOffer})
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

  /**
   * Debug method to create and log a sample credential structure.
   * This helps visualize the fields of an issued credential.
   */
  public async debugCredentialStructure() {
    // Sample credential data
    const sampleCredentialData = {
      given_name: "Juan",
      family_name: "Pérez",
      birth_date: "1990-01-01",
      document_number: "12345678",
    };

    try {
      // Create a sample W3C Verifiable Credential (unsigned for debug)
      const credential = {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        type: ["VerifiableCredential", "MyCredentialType"],
        issuer: ISSUER_ID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: "did:key:z6Mkexample", // Placeholder DID
          ...sampleCredentialData,
        },
      };

      console.log(`\n======================================================`);
      console.log(`🔍 DEBUG: ESTRUCTURA DE LA CREDENCIAL`);
      console.log(`======================================================`);
      console.log(`Credencial de Muestra (sin firmar):`, JSON.stringify(credential, null, 2));
      console.log(`Campos del Credential Subject:`, JSON.stringify(credential.credentialSubject, null, 2));
      console.log(`Tipos de Credencial:`, credential.type);
      console.log(`Issuer:`, credential.issuer);
      console.log(`Fecha de Emisión:`, credential.issuanceDate);
      console.log(`======================================================\n`);

      return credential;
    } catch (error) {
      console.error("Error creating debug credential:", error);
      throw error;
    }
  }
  /**
   * Lists recent issuance sessions and prints the raw SD-JWT credential.
   * Paste the output into https://jwt.io to inspect the payload structure.
   */
  public async debugIssuanceSessions() {
    const { OpenId4VcIssuanceSessionRepository } = await import('@credo-ts/openid4vc');
    const repo = this.agent.dependencyManager.resolve(OpenId4VcIssuanceSessionRepository);
    const sessions = await repo.getAll(this.agent.context);

    console.log(`\n======================================================`);
    console.log(`🔍 DEBUG: SESIONES DE ISSUANCE (${sessions.length} encontradas)`);
    console.log(`======================================================`);

    const result: any[] = [];

    for (const session of sessions) {
      const s = session as any;
      console.log(`\n--- Sesion ID: ${s.id} ---`);
      console.log(`  Estado: ${s.state}`);
      console.log(`  credentialConfigurationIds: ${JSON.stringify(s.credentialConfigurationIds)}`);

      const issued: any[] = s.issuedCredentials ?? s.credentials ?? [];
      console.log(`  issuedCredentials count: ${issued.length}`);

      for (const cred of issued) {
        console.log(`\n  🧠 RAW CREDENTIAL:`);
        console.log(`  ${JSON.stringify(cred)}`);

        if (typeof cred === 'string') {
          const payloadB64 = (cred.split('~')[0] ?? '').split('.')[1];
          if (payloadB64) {
            try {
              const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
              console.log(`\n  📦 PAYLOAD DECODIFICADO:`);
              console.log(JSON.stringify(payload, null, 2));
            } catch (e) {
              console.log('  Error decodificando base64url:', e);
            }
          }
        }
      }

      console.log(`\n  📋 TODOS LOS CAMPOS DE LA SESION:`);
      console.log(JSON.stringify(s, null, 2));

      result.push({
        id: s.id,
        state: s.state,
        credentialConfigurationIds: s.credentialConfigurationIds,
        rawCredentials: issued,
        fullSession: s,
      });
    }

    console.log(`\n======================================================\n`);
    return result;
  }
}
