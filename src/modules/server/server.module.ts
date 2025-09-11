import { Module } from "@nestjs/common"
import { TypeOrmExModule } from "src/common/typeorm-ex.module"
import { ServerController } from "src/modules/server/controllers/server.controller"
import { ServerRepository } from "src/modules/server/repositories/server.repository"
import { ServerService } from "src/modules/server/services/server.service"
import { SSHService } from "src/modules/server/services/ssh.service"

@Module({
	controllers: [ServerController],
	imports: [TypeOrmExModule.forFeature([ServerRepository])],
	providers: [ServerService, SSHService],
})
export class ServerModule {}
