import { Agent } from "@credo-ts/core";
import { Pool } from "pg";
import { envs } from "../../../config/envs";
import * as crypto from "crypto";

const STATUS_LIST_SIZE = 131072;

export interface CredentialStatusEntry {
  credentialId: string;
  index: number;
  revoked: boolean;
  issuedAt: Date;
}

export class StatusListService {
  private pool: Pool;
  private initialized = false;

  constructor() {
    this.pool = new Pool({
      connectionString: envs.DATABASE_URL,
    });
  }

  private async initialize() {
    if (this.initialized) return;

    const client = await this.pool.connect();
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS status_list (
          id TEXT PRIMARY KEY DEFAULT 'main',
          encoded_list TEXT NOT NULL,
          bitstring_size INTEGER NOT NULL DEFAULT ${STATUS_LIST_SIZE},
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS credential_status (
          credential_id TEXT PRIMARY KEY,
          status_list_id TEXT NOT NULL DEFAULT 'main',
          index INTEGER NOT NULL,
          revoked BOOLEAN NOT NULL DEFAULT FALSE,
          issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);

      await client.query(`
        CREATE INDEX IF NOT EXISTS idx_credential_status_index 
        ON credential_status(status_list_id, index);
      `);

      this.initialized = true;
    } finally {
      client.release();
    }
  }

  public async getOrCreateStatusList(): Promise<Buffer> {
    await this.initialize();

    const result = await this.pool.query(
      "SELECT encoded_list FROM status_list WHERE id = 'main'"
    );

    if (result.rows.length > 0) {
      return Buffer.from(result.rows[0].encoded_list, "base64");
    }

    const bitstring = Buffer.alloc(STATUS_LIST_SIZE / 8, 0);
    const encoded = bitstring.toString("base64");

    await this.pool.query(
      "INSERT INTO status_list (id, encoded_list) VALUES ('main', $1)",
      [encoded]
    );

    return bitstring;
  }

  public async getNextAvailableIndex(): Promise<number> {
    await this.initialize();

    const result = await this.pool.query(
      `SELECT index FROM credential_status 
       WHERE status_list_id = 'main' AND revoked = FALSE
       ORDER BY index
       LIMIT 1`
    );

    if (result.rows.length > 0) {
      return result.rows[0].index;
    }

    const countResult = await this.pool.query(
      "SELECT COUNT(*) as count FROM credential_status WHERE status_list_id = 'main'"
    );
    const currentCount = parseInt(countResult.rows[0].count, 10);

    if (currentCount < STATUS_LIST_SIZE) {
      return currentCount;
    }

    throw new Error("Status list is full");
  }

  public async registerCredential(credentialId: string): Promise<number> {
    await this.initialize();

    const existing = await this.pool.query(
      "SELECT index FROM credential_status WHERE credential_id = $1",
      [credentialId]
    );

    if (existing.rows.length > 0) {
      return existing.rows[0].index;
    }

    const index = await this.getNextAvailableIndex();

    await this.pool.query(
      `INSERT INTO credential_status (credential_id, status_list_id, index) 
       VALUES ($1, 'main', $2)`,
      [credentialId, index]
    );

    return index;
  }

  public async revokeCredential(credentialId: string): Promise<void> {
    await this.initialize();

    const result = await this.pool.query(
      "SELECT index FROM credential_status WHERE credential_id = $1 AND revoked = FALSE",
      [credentialId]
    );

    if (result.rows.length === 0) {
      throw new Error(`Credential ${credentialId} not found or already revoked`);
    }

    const index = result.rows[0].index;
    const bitstring = await this.getOrCreateStatusList();

    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;
    const byteValue = bitstring[byteIndex];
    if (byteValue === undefined) {
      throw new Error(`Invalid byte index: ${byteIndex}`);
    }
    bitstring[byteIndex] = byteValue | (1 << bitIndex);

    await this.updateStatusList(bitstring);
    await this.markAsRevoked(credentialId);
  }

  public async isCredentialRevoked(credentialId: string): Promise<boolean> {
    await this.initialize();

    const result = await this.pool.query(
      "SELECT revoked FROM credential_status WHERE credential_id = $1",
      [credentialId]
    );

    if (result.rows.length === 0) {
      return false;
    }

    return result.rows[0].revoked;
  }

  private async updateStatusList(bitstring: Buffer): Promise<void> {
    await this.initialize();
    const encoded = bitstring.toString("base64");

    await this.pool.query(
      "UPDATE status_list SET encoded_list = $1, updated_at = CURRENT_TIMESTAMP WHERE id = 'main'",
      [encoded]
    );
  }

  private async markAsRevoked(credentialId: string): Promise<void> {
    await this.initialize();
    await this.pool.query(
      "UPDATE credential_status SET revoked = TRUE WHERE credential_id = $1",
      [credentialId]
    );
  }

  public async getStatusListDocument(): Promise<{
    "@context": string | string[];
    type: string;
    statusListCredential: string;
    statusListIndex: number;
    statusPurpose: string;
    encodedList: string;
  }> {
    const bitstring = await this.getOrCreateStatusList();
    const encodedList = bitstring.toString("base64url");

    return {
      "@context": [
        "https://www.w3.org/ns/credentials/status/v1",
        "https://w3c-ccg.github.io/vc-status-list-2021/contexts/v1.jsonld",
      ],
      type: "StatusList2021",
      statusListCredential: `https://${envs.DOMAIN.replace(/^https?:\/\//, "")}/.well-known/status-list.json`,
      statusListIndex: STATUS_LIST_SIZE,
      statusPurpose: "revocation",
      encodedList,
    };
  }

  public async getCredentialStatusEntry(
    credentialId: string
  ): Promise<CredentialStatusEntry | null> {
    await this.initialize();

    const result = await this.pool.query(
      `SELECT credential_id, index, revoked, issued_at 
       FROM credential_status WHERE credential_id = $1`,
      [credentialId]
    );

    if (result.rows.length === 0) {
      return null;
    }

    return {
      credentialId: result.rows[0].credential_id,
      index: result.rows[0].index,
      revoked: result.rows[0].revoked,
      issuedAt: result.rows[0].issued_at,
    };
  }
}