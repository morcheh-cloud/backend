import { Module } from "@nestjs/common";
import { ThrottlerModule } from "@nestjs/throttler";
import { TypeOrmModule } from "@nestjs/typeorm/dist/typeorm.module";
import { databaseConfig } from "src/config/database.config";
import { RATE_LIMIT_CONFIG } from "src/config/ratelimit.config";
import { CommonModule } from "./common/common.module";
import { AnsibleModule } from "./modules/ansible/ansible.module";
import { AuthModule } from "./modules/auth/auth.module";
import { ServerModule } from "./modules/server/server.module";
import { UserModule } from "./modules/user/user.module";

@Module({
  controllers: [],
  imports: [
    TypeOrmModule.forRoot(databaseConfig),
    ThrottlerModule.forRoot(RATE_LIMIT_CONFIG),
    AuthModule,
    UserModule,
    CommonModule,
    AnsibleModule,
    ServerModule,
  ],
  providers: [],
})
export class AppModule {}
