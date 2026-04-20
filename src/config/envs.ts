import "dotenv/config";
import { get } from "env-var";

export const envs = {
  PORT: get("PORT").required().asPortNumber(),
  VAULT_ADDR: get("VAULT_ADDR").default("http://localhost:8200").asString(),
  VAULT_TOKEN: get("VAULT_TOKEN").asString(),
  VAULT_TRANSIT_PATH: get("VAULT_TRANSIT_PATH").default("transit").asString(),
  DATABASE_URL: get("DATABASE_URL")
    .default("postgres://postgres:postgres@localhost:5432/credo")
    .asString(),
  DOMAIN: get("DOMAIN").default("localhost:3000").asString(),
};
