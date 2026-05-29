import { StatusListService } from "./status-list.service";

export class RevocationService {
  constructor(private readonly statusListService: StatusListService) {}

  public async revokeCredential(credentialId: string): Promise<void> {
    await this.statusListService.revokeCredential(credentialId);
  }

  public async isCredentialRevoked(credentialId: string): Promise<boolean> {
    return this.statusListService.isCredentialRevoked(credentialId);
  }

  public async registerCredential(credentialId: string): Promise<number> {
    return this.statusListService.registerCredential(credentialId);
  }
}