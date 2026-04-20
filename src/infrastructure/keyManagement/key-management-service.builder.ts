import { AgentContext, Kms } from "@credo-ts/core";
import { envs } from "../../config/envs";
import crypto from "crypto";
import { PublicJwk } from "@credo-ts/core/kms";

interface KmsConfig {
  mode: "vault";
  vaultUrl: string;
  vaultToken?: string;
  vaultTransitPath: string;
}

interface VaultTransitKeyResponse {
  data: {
    keys: {
      [version: string]: {
        public_key?: string;
      };
    };
  };
}

interface VaultTransitSignResponse {
  data: {
    signature: string;
  };
}

interface VaultTransitVerifyResponse {
  data: {
    valid: boolean;
  };
}

interface VaultTransitEncryptResponse {
  data: {
    ciphertext: string;
  };
}

interface VaultTransitDecryptResponse {
  data: {
    plaintext: string;
  };
}

export function buildKeyManagementModule(
  config: KmsConfig,
): Kms.KeyManagementModule {
  switch (config.mode) {
    case "vault":
      return new Kms.KeyManagementModule({
        backends: [
          new VaultKeyManagementModule(
            config.vaultUrl,
            // config.vaultToken,
            config.vaultTransitPath,
          ),
        ],
      });
  }
}

export class VaultKeyManagementModule implements Kms.KeyManagementService {
  public backend = "vault";
  private readonly transitPath: string;
  /** Maps Credo-internal keyIds (e.g. base58 fingerprints) -> Vault key names */
  private readonly keyIdToVaultName = new Map<string, string>();

  private get vaultUrl() {
    return `${this.baseUrl}/v1/${this.transitPath}`;
  }

  constructor(
    private readonly baseUrl: string,
    // private readonly token: string,
    transitPath?: string,
  ) {
    this.transitPath = (transitPath ?? "transit").replace(/\/$/, "");
  }
  private get headers() {
    return {
      "X-Vault-Token": envs.VAULT_TOKEN,
      "Content-Type": "application/json",
    };
  }

  public isOperationSupported(
    _agentContext: AgentContext,
    operation: Kms.KmsOperation,
  ): boolean {
    switch (operation.operation) {
      case "createKey":
        return (
          (operation.type.kty === "EC" && operation.type.crv === "P-256") ||
          (operation.type.kty === "OKP" && operation.type.crv === "Ed25519") ||
          (operation.type.kty === "EC" && operation.type.crv === "secp256k1")
        );
      case "sign":
      case "verify":
        return ["ES256", "EdDSA", "ES256K"].includes(operation.algorithm);
      case "encrypt":
      case "decrypt":
      case "deleteKey":
      case "randomBytes":
        return true;
      default:
        return false;
    }
  }

  public async getPublicKey(
    _agentContext: AgentContext,
    keyId: string,
  ): Promise<Kms.KmsJwkPublic | null> {
    // Resolve Credo internal keyId (fingerprint/legacy) to actual Vault key name
    const vaultKeyName = this.keyIdToVaultName.get(keyId) ?? keyId;

    try {
      const response = await fetch(`${this.vaultUrl}/keys/${vaultKeyName}`, {
        headers: this.headers,
      });

      if (response.status === 404) return null;
      if (!response.ok) {
        throw new Error(`Vault error: ${response.statusText}`);
      }

      const data = (await response.json()) as VaultTransitKeyResponse;
      const latestVersion = Object.keys(data.data.keys).sort().pop();
      if (!latestVersion) return null;

      const keyData = data.data.keys[latestVersion];
      if (!keyData) return null;

      let publicKeyPem = keyData.public_key;
      // Symmetric keys won't have a public_key field in Vault
      if (!publicKeyPem) {
        return {
          kty: "oct",
          kid: keyId,
        } as Kms.KmsJwkPublic;
      }

      // Sanitize PEM: ensure correct line endings and trim whitespace
      publicKeyPem = publicKeyPem.trim() + "\n";

      const extractBase64 = (pem: string) =>
        pem
          .replace(/-----BEGIN (?:PUBLIC|ANY) KEY-----/, "")
          .replace(/-----END (?:PUBLIC|ANY) KEY-----/, "")
          .replace(/\s/g, "");

      const base64 = extractBase64(publicKeyPem);
      const der = Buffer.from(base64, "base64");

      // Handle raw key bytes (often returned by some Vault configurations or non-standard PEMs)
      if (der.length === 32) {
        // Raw Ed25519 public key
        return {
          kty: "OKP",
          crv: "Ed25519",
          x: der.toString("base64url"),
          kid: keyId,
        } as Kms.KmsJwkPublic;
      }

      if (der.length === 65 && der[0] === 0x04) {
        // Raw uncompressed ECDSA public key (P-256 or secp256k1)
        // We assume P-256 as default if we can't determine, or check crv from the context if available.
        // However, we'll try to use createPublicKey with raw format first.
        try {
          const keyObj = crypto.createPublicKey({
            key: der,
            format: "der", // Actually 'raw' usually but Node has specific requirements
            type: "spki",
          });
          const jwk = keyObj.export({ format: "jwk" }) as any;
          return { ...jwk, kid: keyId };
        } catch {
          // Manual split if Node fails
          return {
            kty: "EC",
            crv: "P-256", // Defaulting to P-256
            x: der.subarray(1, 33).toString("base64url"),
            y: der.subarray(33).toString("base64url"),
            kid: keyId,
          } as Kms.KmsJwkPublic;
        }
      }

      let key: crypto.KeyObject;
      try {
        // Try binary decoding (SPKI/PKCS#8)
        key = crypto.createPublicKey({
          key: der,
          format: "der",
          type: "spki",
        });
      } catch (decoderError) {
        console.warn(
          `Primary decoder failed for key ${keyId} (Length: ${der.length}, Hex: ${der.subarray(0, 12).toString("hex")}), attempting OID-based recovery...`,
        );

        // Ed25519 SPKI OID fallback
        const ed25519Oid = Buffer.from("06032b6570", "hex");
        const oidIndex = der.indexOf(ed25519Oid);

        if (oidIndex !== -1) {
          const bitStringHeader = Buffer.from("032100", "hex");
          const keyIndex = der.indexOf(bitStringHeader, oidIndex);

          if (keyIndex !== -1 && der.length >= keyIndex + 3 + 32) {
            const rawPublicKey = der.subarray(keyIndex + 3, keyIndex + 3 + 32);
            return {
              kty: "OKP",
              crv: "Ed25519",
              x: rawPublicKey.toString("base64url"),
              kid: keyId,
            } as Kms.KmsJwkPublic;
          }
        }

        // Final attempt as PEM string
        try {
          key = crypto.createPublicKey(publicKeyPem);
        } catch (finalError) {
          console.error(`Final crypto decoder failed for key ${keyId}`);
          throw finalError;
        }
      }

      const jwk = key.export({ format: "jwk" }) as {
        kty: "EC" | "OKP" | "RSA" | "oct";
        crv?: string;
        x?: string;
        y?: string;
      };

      return {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
        kid: keyId,
      } as Kms.KmsJwkPublic;
    } catch (error) {
      console.error(`Error getting public key from Vault:`, error);
      return null;
    }
  }

  public async initialize(): Promise<void> {
    try {
      // Optimistically try to enable the transit engine.
      // If it's already enabled, Vault returns 400 "path is already in use".
      const enableResponse = await fetch(
        `${this.baseUrl}/v1/sys/mounts/${this.transitPath}`,
        {
          method: "POST",
          headers: this.headers,
          body: JSON.stringify({ type: "transit" }),
        },
      );

      if (enableResponse.ok || enableResponse.status === 204) {
        console.log(
          `Transit engine successfully enabled at '${this.transitPath}'.`,
        );
      } else if (enableResponse.status === 400) {
        const body = (await enableResponse.json().catch(() => ({}))) as {
          errors?: string[];
        };
        if (
          body.errors &&
          body.errors.some((e: string) => e.includes("path is already in use"))
        ) {
          // Already enabled, this is fine.
          console.log(
            `Transit engine already available at '${this.transitPath}'.`,
          );
        } else {
          console.warn(
            `Unexpected 400 error from Vault when enabling transit: ${JSON.stringify(body.errors)}`,
          );
        }
      } else {
        const body = await enableResponse.text();
        console.error(
          `Failed to enable transit engine: ${enableResponse.statusText}. Response: ${body}`,
        );
      }
    } catch (error) {
      console.error("Error during Vault KMS initialization:", error);
    }
  }

  /** Rebuild the fingerprint->vaultKeyName map by listing all Vault transit keys */
  public async rebuildKeyMappings(agentContext: AgentContext): Promise<void> {
    try {
      const response = await fetch(`${this.vaultUrl}/keys?list=true`, {
        method: "GET",
        headers: this.headers,
      });
      if (!response.ok) return;
      const data = (await response.json()) as { data?: { keys?: string[] } };
      const keyNames = data.data?.keys ?? [];
      for (const name of keyNames) {
        const jwk = await this.getPublicKey(agentContext, name);
        if (!jwk) continue;
        // Always register identity
        this.keyIdToVaultName.set(name, name);
        // Register fingerprint -> vault key name
        try {
          const pubJwkInstance = PublicJwk.fromPublicJwk(jwk as any);
          
          this.keyIdToVaultName.set(pubJwkInstance.fingerprint, name);
          console.debug(`[VaultKMS] Mapped fingerprint ${pubJwkInstance.fingerprint} -> ${name}`);
          
          this.keyIdToVaultName.set(pubJwkInstance.legacyKeyId, name);
          console.debug(`[VaultKMS] Mapped legacyKeyId ${pubJwkInstance.legacyKeyId} -> ${name}`);
        } catch {
          // If fingerprint computation fails, skip
        }
      }
      console.log(
        `[VaultKMS] Rebuilt key mappings for ${keyNames.length} Vault key(s)`,
      );
    } catch (e) {
      console.warn(`[VaultKMS] Could not rebuild key mappings:`, e);
    }
  }

  public async createKey<Type extends Kms.KmsCreateKeyType>(
    agentContext: AgentContext,
    options: Kms.KmsCreateKeyOptions<Type>,
  ): Promise<Kms.KmsCreateKeyReturn<Type>> {
    const keyId = options.keyId ?? crypto.randomUUID();
    const vaultType = this.mapToVaultType(options.type);

    const response = await fetch(`${this.vaultUrl}/keys/${keyId}`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify({ type: vaultType }),
    });

    if (!response.ok && response.status !== 204) {
      const errorBody = await response.text().catch(() => "No body");
      throw new Error(
        `Failed to create key in Vault at path ${this.vaultUrl}/keys/${keyId}: ${response.statusText}. Details: ${errorBody}`,
      );
    }

    const publicJwk = await this.getPublicKey(agentContext, keyId);
    if (!publicJwk)
      throw new Error(`Could not retrieve created public key for kid ${keyId}`);

    // Compute the Credo fingerprint and legacyKeyId and map them to our vault key name
    try {
      const pubJwkInstance = PublicJwk.fromPublicJwk(publicJwk as any);
      
      this.keyIdToVaultName.set(pubJwkInstance.fingerprint, keyId);
      console.debug(`[VaultKMS] Registered fingerprint mapping: ${pubJwkInstance.fingerprint} -> ${keyId}`);
      
      this.keyIdToVaultName.set(pubJwkInstance.legacyKeyId, keyId);
      console.debug(`[VaultKMS] Registered legacyKeyId mapping: ${pubJwkInstance.legacyKeyId} -> ${keyId}`);
    } catch (e) {
      console.warn(
        `[VaultKMS] Could not compute fingerprint for key ${keyId}:`,
        e,
      );
    }
    // Always register identity mapping
    this.keyIdToVaultName.set(keyId, keyId);

    return {
      keyId,
      publicJwk,
    } as Kms.KmsCreateKeyReturn<Type>;
  }

  public async importKey<Jwk extends Kms.KmsJwkPrivate>(
    _agentContext: AgentContext,
    _options: Kms.KmsImportKeyOptions<Jwk>,
  ): Promise<Kms.KmsImportKeyReturn<Jwk>> {
    throw new Error("Import key not implemented for Vault Transit.");
  }

  public async deleteKey(
    _agentContext: AgentContext,
    options: Kms.KmsDeleteKeyOptions,
  ): Promise<boolean> {
    const response = await fetch(`${this.vaultUrl}/keys/${options.keyId}`, {
      method: "DELETE",
      headers: this.headers,
    });
    return response.ok || response.status === 204;
  }

  public async sign(
    _agentContext: AgentContext,
    options: Kms.KmsSignOptions,
  ): Promise<Kms.KmsSignReturn> {
    // Resolve Credo internal keyId to actual Vault key name
    const rawKeyId = options.keyId;
    const vaultKeyName = this.keyIdToVaultName.get(rawKeyId) ?? rawKeyId;

    if (vaultKeyName !== rawKeyId) {
      console.debug(
        `[VaultKMS] Resolved sign keyId: ${rawKeyId} -> ${vaultKeyName}`,
      );
    }

    const input = Buffer.from(options.data).toString("base64");
    const response = await fetch(`${this.vaultUrl}/sign/${vaultKeyName}`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify({ input }),
    });

    if (!response.ok) {
      throw new Error(`Vault sign error: ${response.statusText}`);
    }

    const data = (await response.json()) as VaultTransitSignResponse;
    const signatureVault = data.data.signature; // Format: vault:v1:BASE64
    const signatureBase64 = signatureVault.split(":")[2];
    if (!signatureBase64)
      throw new Error("Invalid signature format received from Vault");
    const signature = new Uint8Array(Buffer.from(signatureBase64, "base64"));

    return { signature };
  }

  public async verify(
    agentContext: AgentContext,
    options: Kms.KmsVerifyOptions,
  ): Promise<Kms.KmsVerifyReturn> {
    const publicJwk =
      "publicJwk" in options.key ? options.key.publicJwk : undefined;

    const keyId = "keyId" in options.key ? options.key.keyId : publicJwk?.kid;

    // If we only have publicJwk and no keyId/kid, we verify locally using standard Node.js crypto
    if (!keyId && publicJwk) {
      try {
        const publicKey = crypto.createPublicKey({
          key: publicJwk as any,
          format: "jwk",
        });
        const dataBuffer = Buffer.from(options.data);
        const signatureBuffer = Buffer.from(options.signature);

        let verified = false;
        if (publicJwk.kty === "OKP" && publicJwk.crv === "Ed25519") {
          verified = crypto.verify(
            undefined,
            dataBuffer,
            publicKey,
            signatureBuffer,
          );
        } else {
          // Fallback algorithm assumption for EC/RSA validation (SHA256)
          // JWT/JWS signatures for ECDSA (ES256) use IEEE P1363 (concatenated r+s format, 64 bytes)
          verified = crypto.verify(
            "SHA256",
            dataBuffer,
            { key: publicKey, dsaEncoding: "ieee-p1363" },
            signatureBuffer,
          );
        }
        return { verified, publicJwk };
      } catch (err: any) {
        throw new Error(
          `Fallback Node crypto verification failed: ${err.message}`,
        );
      }
    }

    if (!keyId) {
      throw new Error(
        "Verification with only publicJwk is not supported by Vault KMS yet.",
      );
    }

    const input = Buffer.from(options.data).toString("base64");
    const signature = `vault:v1:${Buffer.from(options.signature).toString("base64")}`;

    const response = await fetch(`${this.vaultUrl}/verify/${keyId}`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify({ input, signature }),
    });

    if (!response.ok) return { verified: false };

    const data = (await response.json()) as VaultTransitVerifyResponse;
    if (data.data.valid) {
      const jwk = publicJwk ?? (await this.getPublicKey(agentContext, keyId));
      if (!jwk) return { verified: false };
      return { verified: true, publicJwk: jwk };
    }

    return { verified: false };
  }

  public async encrypt(
    _agentContext: AgentContext,
    options: Kms.KmsEncryptOptions,
  ): Promise<Kms.KmsEncryptReturn> {
    const keyId = "keyId" in options.key ? options.key.keyId : undefined;
    if (!keyId) {
      throw new Error("keyId is required for Vault encrypt");
    }

    const plaintext = Buffer.from(options.data).toString("base64");
    const response = await fetch(`${this.vaultUrl}/encrypt/${keyId}`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify({ plaintext }),
    });

    if (!response.ok) {
      throw new Error(`Vault encrypt error: ${response.statusText}`);
    }

    const data = (await response.json()) as VaultTransitEncryptResponse;
    // Vault returns "vault:v1:..." string. We return it as bytes.
    const encryptedData = Buffer.from(data.data.ciphertext);
    return {
      encrypted: new Uint8Array(encryptedData),
    };
  }

  public async decrypt(
    _agentContext: AgentContext,
    options: Kms.KmsDecryptOptions,
  ): Promise<Kms.KmsDecryptReturn> {
    const keyId = "keyId" in options.key ? options.key.keyId : undefined;
    if (!keyId) {
      throw new Error("keyId is required for Vault decrypt");
    }

    const ciphertext = Buffer.from(options.encrypted).toString();
    const response = await fetch(`${this.vaultUrl}/decrypt/${keyId}`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify({ ciphertext }),
    });

    if (!response.ok) {
      throw new Error(`Vault decrypt error: ${response.statusText}`);
    }

    const data = (await response.json()) as VaultTransitDecryptResponse;
    const decryptedData = Buffer.from(data.data.plaintext, "base64");
    return { data: new Uint8Array(decryptedData) };
  }

  public randomBytes(
    _agentContext: AgentContext,
    options: Kms.KmsRandomBytesOptions,
  ): Kms.KmsRandomBytesReturn {
    return crypto.randomBytes(options.length);
  }

  private mapToVaultType(credoType: Kms.KmsCreateKeyType): string {
    if (credoType.kty === "EC") {
      if (credoType.crv === "P-256") return "ecdsa-p256";
      if (credoType.crv === "secp256k1") return "ecdsa-secp256k1";
    }
    if (credoType.kty === "OKP") {
      if (credoType.crv === "Ed25519") return "ed25519";
    }
    throw new Error(
      `Unsupported key type for Vault Transit: ${JSON.stringify(credoType)}`,
    );
  }
}
