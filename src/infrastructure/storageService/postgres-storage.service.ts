import {
  AgentContext,
  BaseRecord,
  BaseRecordConstructor,
  StorageService,
  Query,
  QueryOptions,
  RecordNotFoundError,
  RecordDuplicateError,
  utils,
  JsonTransformer,
} from "@credo-ts/core";
import { Pool } from "pg";
import { envs } from "../../config/envs";

export class PostgresStorageService<
  T extends BaseRecord,
> implements StorageService<T> {
  public supportsCursorPagination = false;
  private pool: Pool;
  private initialized = false;

  constructor() {
    this.pool = new Pool({
      connectionString: envs.DATABASE_URL,
    });
  }

  public async initialize() {
    if (this.initialized) return;

    const client = await this.pool.connect();
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS storage_records (
          id TEXT,
          type TEXT,
          value JSONB,
          tags JSONB,
          PRIMARY KEY (id, type)
        );
      `);
      this.initialized = true;
    } finally {
      client.release();
    }
  }

  public async save(_agentContext: AgentContext, record: T): Promise<void> {
    await this.initialize();
    try {
      const value = record.toJSON();
      const tags = record.getTags();

      await this.pool.query(
        "INSERT INTO storage_records (id, type, value, tags) VALUES ($1, $2, $3, $4)",
        [
          record.id,
          (record.constructor as any).type,
          JSON.stringify(value),
          JSON.stringify(tags),
        ],
      );
    } catch (error: any) {
      if (error.code === "23505") {
        // Unique violation
        throw new RecordDuplicateError(
          `Record with id ${record.id} already exists`,
          { recordType: (record.constructor as any).type },
        );
      }
      throw error;
    }
  }

  public async update(_agentContext: AgentContext, record: T): Promise<void> {
    await this.initialize();
    const value = record.toJSON();
    const tags = record.getTags();
    const type = (record.constructor as any).type;

    const result = await this.pool.query(
      "UPDATE storage_records SET value = $3, tags = $4 WHERE id = $1 AND type = $2",
      [record.id, type, JSON.stringify(value), JSON.stringify(tags)],
    );

    if (result.rowCount === 0) {
      throw new RecordNotFoundError(
        `Record with id ${record.id} and type ${type} not found`,
        { recordType: type },
      );
    }
  }

  public async delete(_agentContext: AgentContext, record: T): Promise<void> {
    await this.deleteById(_agentContext, record.constructor as any, record.id);
  }

  public async deleteById(
    _agentContext: AgentContext,
    recordClass: BaseRecordConstructor<T>,
    id: string,
  ): Promise<void> {
    await this.initialize();
    const type = recordClass.type;
    const result = await this.pool.query(
      "DELETE FROM storage_records WHERE id = $1 AND type = $2",
      [id, type],
    );

    if (result.rowCount === 0) {
      throw new RecordNotFoundError(
        `Record with id ${id} and type ${type} not found`,
        { recordType: type },
      );
    }
  }

  public async getById(
    _agentContext: AgentContext,
    recordClass: BaseRecordConstructor<T>,
    id: string,
  ): Promise<T> {
    await this.initialize();
    const type = recordClass.type;
    const result = await this.pool.query(
      "SELECT value FROM storage_records WHERE id = $1 AND type = $2",
      [id, type],
    );

    if (result.rows.length === 0) {
      throw new RecordNotFoundError(
        `Record with id ${id} and type ${type} not found`,
        { recordType: type },
      );
    }

    return this.instanceRecord(recordClass, result.rows[0].value);
  }

  public async getAll(
    _agentContext: AgentContext,
    recordClass: BaseRecordConstructor<T>,
  ): Promise<T[]> {
    await this.initialize();
    const type = recordClass.type;
    const result = await this.pool.query(
      "SELECT value FROM storage_records WHERE type = $1",
      [type],
    );

    return result.rows.map((row) =>
      this.instanceRecord(recordClass, row.value),
    );
  }

  public async findByQuery(
    _agentContext: AgentContext,
    recordClass: BaseRecordConstructor<T>,
    query: Query<T>,
    queryOptions?: QueryOptions,
  ): Promise<T[]> {
    await this.initialize();
    const type = recordClass.type;

    // Simple implementation of query. For now only supports simple equality on tags.
    // In Credo, a simple Query is Record<string, string | string[] | undefined>

    let sql = "SELECT value FROM storage_records WHERE type = $1";
    const params: any[] = [type];

    // Helper to build a WHERE clause from a query object
    const buildWhere = (q: any): string => {
      if (q.$and && Array.isArray(q.$and)) {
        const clauses = q.$and
          .map((subQ: any) => buildWhere(subQ))
          .filter(Boolean);
        return clauses.length > 0 ? `(${clauses.join(" AND ")})` : "";
      }
      if (q.$or && Array.isArray(q.$or)) {
        const clauses = q.$or
          .map((subQ: any) => buildWhere(subQ))
          .filter(Boolean);
        return clauses.length > 0 ? `(${clauses.join(" OR ")})` : "";
      }
      if (q.$not) {
        const clause = buildWhere(q.$not);
        return clause ? `(NOT ${clause})` : "";
      }

      // Simple exact match
      if (Object.keys(q).length > 0) {
        const paramIndex = params.length + 1;
        params.push(JSON.stringify(q));
        return `tags @> $${paramIndex}`;
      }
      return "";
    };

    const whereClause = buildWhere(query);
    if (whereClause) {
      sql += ` AND ${whereClause}`;
    }

    if (queryOptions?.limit) {
      sql += ` LIMIT ${queryOptions.limit}`;
    }
    if (queryOptions?.offset) {
      sql += ` OFFSET ${queryOptions.offset}`;
    }

    const result = await this.pool.query(sql, params);
    return result.rows.map((row) =>
      this.instanceRecord(recordClass, row.value),
    );
  }

  private instanceRecord(recordClass: BaseRecordConstructor<T>, value: any): T {
    // Credo records must be properly deserialized to instantiate nested classes
    // like Metadata, to avoid "this.metadata.get is not a function" errors.
    const record = JsonTransformer.fromJSON(value, recordClass);
    return record;
  }
}
