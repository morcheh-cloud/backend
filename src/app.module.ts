import { Module } from "@nestjs/common";
import { ThrottlerModule } from "@nestjs/throttler";
import { TypeOrmModule } from "@nestjs/typeorm";
import { CommonModule } from "src/common/common.module";
import { databaseConfig } from "src/config/database.config";
import { RATE_LIMIT_CONFIG } from "src/config/ratelimit.config";
import { AnsibleModule } from "src/modules/ansible/ansible.module";
import { AuthModule } from "src/modules/auth/auth.module";
import { ServerModule } from "src/modules/server/server.module";
import { UserModule } from "src/modules/user/user.module";

@Module({
  controllers: [],
  imports: [
    TypeOrmModule.forRoot(databaseConfig),
    ThrottlerModule.forRoot(RATE_LIMIT_CONFIG),
    AuthModule,
    UserModule,
    CommonModule,
    ServerModule,
    AnsibleModule,
  ],
  providers: [],
})
export class AppModule {}
