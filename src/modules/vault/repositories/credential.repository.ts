import { BaseRepository } from "src/common/base/base.repository"
import { EntityRepository } from "src/common/decorators/typeorm-ex.decorator"
import { Credential } from "src/modules/vault/entities/credential.entity"

@EntityRepository(Credential)
export class CredentialRepository extends BaseRepository<Credential> {}
