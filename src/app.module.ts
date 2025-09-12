import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { ScheduleModule } from "@nestjs/schedule";
import { TypeOrmModule } from "@nestjs/typeorm";
import { CommonModule } from "src/common/common.module";
import { JWT_CONFIG } from "src/config/app.config";
import { databaseConfig } from "src/config/database.config";
import { AccountModule } from "src/modules/account/account.module";
import { AnsibleModule } from "src/modules/ansible/ansible.module";
import { AuthModule } from "src/modules/auth/auth.module";
import { ServerModule } from "src/modules/server/server.module";
import { UserModule } from "src/modules/user/user.module";
import { DirectoryModule } from "./modules/directory/directory.module";
import { LogModule } from "./modules/log/log.module";
import { NotificationModule } from "./modules/notification/notification.module";
import { SettingModule } from "./modules/setting/setting.module";
import { VaultModule } from "./modules/vault/vault.module";
import { WorkspaceModule } from "./modules/workspace/workspace.module";

@Module({
  controllers: [],
  imports: [
    JwtModule.register({
      global: true,
      secret: JWT_CONFIG.secret,
      signOptions: { expiresIn: JWT_CONFIG.expiresIn },
    }),
    TypeOrmModule.forRoot(databaseConfig),
    ScheduleModule.forRoot(),
    AuthModule,
    UserModule,
    CommonModule,
    ServerModule,
    AnsibleModule,
    VaultModule,
    WorkspaceModule,
    AccountModule,
    SettingModule,
    NotificationModule,
    LogModule,
    DirectoryModule,
  ],
  providers: [],
})
export class AppModule {}
