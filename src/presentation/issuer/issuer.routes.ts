import { Router } from "express";
import { IssuerController } from "./issuer.controller";
import { WellKnownService } from "./services/well-known.service";
import { Agent } from "@credo-ts/core";

import { CredentialsService } from "./services/credentials.service";

export class IssuerRoutes {
  static routes(agent: Agent): Router {
    const router = Router();

    const wellKnownService = new WellKnownService(agent);
    const credentialsService = new CredentialsService(agent);
    const controller = new IssuerController(
      wellKnownService,
      credentialsService,
    );

    router.get("/.well-known/did.json", controller.getDidDocument);

    router.get("/.well-known/jwks.json", controller.getJsonWebKey);

    router.post("/openid4vci/credential-offer", controller.getCredentialOffer);

    return router;
  }
}
