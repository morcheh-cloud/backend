import { Global, Module } from "@nestjs/common"
import { TypeOrmExModule } from "src/common/typeorm-ex.module"
import { CredentialController } from "src/modules/vault/controllers/credential.controller"
import { CredentialRepository } from "src/modules/vault/repositories/credential.repository"
import { CredentialService } from "src/modules/vault/services/vault.service"

@Global()
@Module({
	controllers: [CredentialController],
	exports: [CredentialService],
	imports: [TypeOrmExModule.forFeature([CredentialRepository])],
	providers: [CredentialService],
})
export class VaultModule {}
