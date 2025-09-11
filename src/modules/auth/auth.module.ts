import { Module } from "@nestjs/common"
import { TypeOrmExModule } from "src/common/typeorm-ex.module"
import { AuthController } from "src/modules/auth/controllers/auth.controller"
import { AuthService } from "src/modules/auth/services/auth.service"
import { UserRepository } from "src/modules/user/repositories/user.repository"

@Module({
	controllers: [AuthController],
	imports: [TypeOrmExModule.forFeature([UserRepository])],
	providers: [AuthService],
})
export class AuthModule {}
