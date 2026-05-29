import { Request, Response } from "express";
import { WellKnownService } from "./services/well-known.service";
import { CredentialsService } from "./services/credentials.service";
import { StatusListService } from "./services/status-list.service";
import { RevocationService } from "./services/revocation.service";

export class IssuerController {
  constructor(
    public readonly wellKnownService: WellKnownService,
    public readonly credentialsService: CredentialsService,
  ) {
    this.statusListService = new StatusListService();
    this.revocationService = new RevocationService(this.statusListService);
  }

  private statusListService: StatusListService;
  private revocationService: RevocationService;

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

  public getStatusList = async (req: Request, res: Response) => {
    try {
      const data = await this.statusListService.getStatusListDocument();
      res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: "Failed to get status list", details: error instanceof Error ? error.message : String(error) });
    }
  };

  public revokeCredential = async (req: Request, res: Response) => {
    try {
      const { credentialId } = req.body;
      if (!credentialId) {
        res.status(400).json({ error: "credentialId is required" });
        return;
      }
      await this.revocationService.revokeCredential(credentialId);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ error: "Failed to revoke credential", details: error instanceof Error ? error.message : String(error) });
    }
  };

  public checkCredentialStatus = async (req: Request, res: Response) => {
    try {
      const credentialId = req.params.credentialId as string;
      if (!credentialId) {
        res.status(400).json({ error: "credentialId is required" });
        return;
      }
      const isRevoked = await this.revocationService.isCredentialRevoked(credentialId);
      const status = await this.statusListService.getCredentialStatusEntry(credentialId);
      res.json({ credentialId, revoked: isRevoked, status });
    } catch (error) {
      res.status(500).json({ error: "Failed to check credential status", details: error instanceof Error ? error.message : String(error) });
    }
  };
}
