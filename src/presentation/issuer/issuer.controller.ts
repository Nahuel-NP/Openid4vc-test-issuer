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

  public debugCredential = async (req: Request, res: Response) => {
    try {
      const data = await this.credentialsService.debugCredentialStructure();
      res.json({ message: "Debug credential logged to console", credential: data });
    } catch (error) {
      res.status(500).json({ error: "Failed to debug credential", details: error instanceof Error ? error.message : String(error) });
    }
  };

  public debugIssuanceSessions = async (req: Request, res: Response) => {
    try {
      const data = await this.credentialsService.debugIssuanceSessions();
      res.json({ sessions: data });
    } catch (error) {
      res.status(500).json({ error: "Failed to list sessions", details: error instanceof Error ? error.message : String(error) });
    }
  };
}
