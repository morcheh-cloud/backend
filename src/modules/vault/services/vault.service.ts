import { Injectable } from "@nestjs/common"
import { decryptText } from "src/lib/encryption"
import { Credential } from "src/modules/vault/entities/credential.entity"

@Injectable()
export class CredentialService {
	// constructor(private credentialRepository: CredentialRepository) {}

	decryptCredentials(credential: Credential): Credential {
		credential.password = decryptText(credential.password)
		credential.username = decryptText(credential.username)
		credential.metadata = decryptText(credential.metadata)
		credential.token = decryptText(credential.token)
		return credential
	}
}
