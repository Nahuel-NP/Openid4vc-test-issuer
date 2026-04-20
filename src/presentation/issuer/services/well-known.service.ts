import { Agent, DidDocument, VerificationMethod } from "@credo-ts/core";
import { envs } from "../../../config/envs";

export class WellKnownService {
  constructor(private readonly agent: Agent) {}



  public getDidDocument = async () => {
    // Strip protocol prefix: did:web does not accept 'https://' or 'http://'
    const rawDomain = envs.DOMAIN.replace(/^https?:\/\//, "");
    const did = `did:web:${rawDomain}`;
    const keyId = "issuer-key";

    // Try to get existing key first to avoid duplicates
    let publicJwk: any = null;
    try {
      publicJwk = await this.agent.kms.getPublicKey({
        keyId,
        backend: "vault",
      });
    } catch (error) {
      // Key not yet registered in Credo — will be created below.
      console.debug("issuer-key not found in KMS, will create:", (error as Error).message);
    }

    if (!publicJwk) {
      const key = await this.agent.kms.createKey({
        keyId,
        backend: "vault",
        type: {
          kty: "OKP",
          crv: "Ed25519",
        },
      });
      publicJwk = key.publicJwk;
    }

    const verificationMethod = new VerificationMethod({
      id: `${did}#owner`,
      type: "JsonWebKey2020",
      controller: did,
      publicKeyJwk: publicJwk,
    });

    const didDocument = new DidDocument({
      id: did,
      verificationMethod: [verificationMethod],
      authentication: [verificationMethod.id],
      assertionMethod: [verificationMethod.id],
    });

    // Check if DID is already imported. If it is, delete it using internal repository so we can freshen the Document format
    const { DidRepository } = await import("@credo-ts/core");
    const didRepository = this.agent.dependencyManager.resolve(DidRepository);
    const existingRecords = await didRepository.findByQuery(this.agent.context, { did });
    for (const record of existingRecords) {
      await didRepository.delete(this.agent.context, record);
    }

    await this.agent.dids.import({
      did,
      didDocument,
    });

    return didDocument.toJSON();
  };

  getJsonWebKey = async () => {
    const keyId = "issuer-key";
    const publicJwk = await this.agent.kms.getPublicKey({
      keyId,
      backend: "vault",
    });
    return {
      keys: [publicJwk],
    };
  };
}
