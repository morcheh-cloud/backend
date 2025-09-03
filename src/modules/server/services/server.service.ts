import { Injectable } from "@nestjs/common";
import { SaveServerPayload } from "src/modules/server/DTOs/server.dto";
import { ServerRepository } from "src/modules/server/repositories/server.repository";
import { CredentialService } from "src/modules/vault/services/vault.service";

@Injectable()
export class ServerService {
  constructor(
    private readonly serverRepository: ServerRepository,
    private credentialService: CredentialService
  ) {}

  async create(
    userId: number,
    workspaceId: number,
    payload: SaveServerPayload
  ) {
    const credential = await this.credentialService.create(
      userId,
      workspaceId,
      payload
    );

    const server = await this.serverRepository.save({
      ...payload,
      credential,
      user: { id: userId },
      workspace: { id: workspaceId },
    });

    return server;
  }
}
