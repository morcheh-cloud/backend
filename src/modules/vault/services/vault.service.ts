import { Injectable } from "@nestjs/common";
import { decryptText, encryptText } from "src/lib/encryption";
import { SaveCredentialPayload } from "src/modules/vault/DTOs/credentail.dto";
import { Credential } from "src/modules/vault/entities/credential.entity";
import { CredentialRepository } from "src/modules/vault/repositories/credential.repository";

@Injectable()
export class CredentialService {
  constructor(private credentialRepository: CredentialRepository) {}

  decryptCredentials(credential: Credential): Credential {
    credential.password = decryptText(credential.password);
    credential.username = decryptText(credential.username);
    credential.metadata = decryptText(credential.metadata);
    credential.token = decryptText(credential.token);
    return credential;
  }

  encryptCredentials(credential: Partial<Credential>) {
    credential.password = encryptText(credential.password);
    credential.username = encryptText(credential.username);
    credential.metadata = encryptText(credential.metadata);
    credential.token = encryptText(credential.token);
    return credential;
  }

  async create(
    userId: number,
    workspaceId: number,
    payload: SaveCredentialPayload
  ) {
    const data = this.encryptCredentials({
      ...payload,
    });

    const credential = await this.credentialRepository.createAndSave({
      ...data,
      user: { id: userId },
      workspace: { id: workspaceId },
    });

    return credential;
  }
}
