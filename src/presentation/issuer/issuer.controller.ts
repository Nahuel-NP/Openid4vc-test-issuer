import { Request, Response } from "express";
import { WellKnownService } from "./services/well-known.service";
import { CredentialsService } from "./services/credentials.service";

export class IssuerController {
  constructor(
    public readonly wellKnownService: WellKnownService,
    public readonly credentialsService: CredentialsService,
  ) {}

  public getDidDocument = async (req: Request, res: Response) => {
    const data = await this.wellKnownService.getDidDocument();
    res.json(data);
  };

  public getJsonWebKey = async (req: Request, res: Response) => {
    const data = await this.wellKnownService.getJsonWebKey();
    res.json(data);
  };

  public getCredentialOffer = async (req: Request, res: Response) => {
    const data = await this.credentialsService.createCredentialOffer();
    res.json(data);
  };
}
