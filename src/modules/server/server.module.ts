import { Module } from "@nestjs/common";
import { TypeOrmExModule } from "src/common/typeorm-ex.module";
import { ServerController } from "src/modules/server/controllers/server.controller";
import { ServerRepository } from "src/modules/server/repositories/server.repository";

@Module({
  controllers: [ServerController],
  imports: [TypeOrmExModule.forFeature([ServerRepository])],
})
export class ServerModule {}
