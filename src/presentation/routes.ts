import { Router } from "express";
import { Agent } from "@credo-ts/core";
import { IssuerRoutes } from "./issuer/issuer.routes";

export class AppRoutes {
  static routes(agent: Agent): Router {
    const issuerRoutes = Router();
    issuerRoutes.use("/", IssuerRoutes.routes(agent));
    return issuerRoutes;
  }
}
