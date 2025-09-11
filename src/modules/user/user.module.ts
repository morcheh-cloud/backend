import { Module } from "@nestjs/common"
import { TypeOrmExModule } from "src/common/typeorm-ex.module"
import { UserRepository } from "src/modules/user/repositories/user.repository"
import { UserService } from "src/modules/user/services/user.service"

@Module({
	exports: [UserService],
	imports: [TypeOrmExModule.forFeature([UserRepository])],
	providers: [UserService],
})
export class UserModule {}
