import { Module } from "@nestjs/common";
import { TypeOrmExModule } from "src/common/typeorm-ex.module";
import { UserRepository } from "src/modules/user/repositories/user.repository";

@Module({
  imports: [TypeOrmExModule.forFeature([UserRepository])],
})
export class UserModule {}
