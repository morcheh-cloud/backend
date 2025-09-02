import { Module } from "@nestjs/common";
import { TypeOrmExModule } from "src/common/typeorm-ex.module";
import { CredentialRepository } from "src/modules/vault/repositories/credential.repository";
import { CredentialService } from "src/modules/vault/services/vault.service";

@Module({
  exports: [CredentialService],
  imports: [TypeOrmExModule.forFeature([CredentialRepository])],
  providers: [CredentialService],
})
export class VaultModule {}
