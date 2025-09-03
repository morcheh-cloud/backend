import { Module } from "@nestjs/common"
import { JwtModule } from "@nestjs/jwt"
import { TypeOrmExModule } from "src/common/typeorm-ex.module"
import { JWT_CONFIG } from "src/config/app.config"
import { UserRepository } from "src/modules/user/repositories/user.repository"

@Module({
	imports: [
		TypeOrmExModule.forFeature([UserRepository]),
		JwtModule.register({
			secret: JWT_CONFIG.secret,
			signOptions: { expiresIn: JWT_CONFIG.expiresIn },
		}),
	],
})
export class AuthModule {}
