import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { JWT_CONFIG } from "src/config/app.config";

@Module({
  imports: [
    JwtModule.register({
      global: true,
      secret: JWT_CONFIG.secret,
      signOptions: { expiresIn: JWT_CONFIG.expiresIn },
    }),
  ],
})
export class AuthModule {}
