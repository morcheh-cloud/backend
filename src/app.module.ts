import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import { CommonModule } from "src/common/common.module";
import { databaseConfig } from "src/config/database.config";
import { AnsibleModule } from "src/modules/ansible/ansible.module";
import { AuthModule } from "src/modules/auth/auth.module";
import { ServerModule } from "src/modules/server/server.module";
import { UserModule } from "src/modules/user/user.module";
import { VaultModule } from "./modules/vault/vault.module";
import { WorkspaceModule } from "./modules/workspace/workspace.module";

@Module({
  controllers: [],
  imports: [
    TypeOrmModule.forRoot(databaseConfig),
    AuthModule,
    UserModule,
    CommonModule,
    ServerModule,
    AnsibleModule,
    VaultModule,
    WorkspaceModule,
  ],
  providers: [],
})
export class AppModule {}
