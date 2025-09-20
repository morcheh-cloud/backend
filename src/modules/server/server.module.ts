import { Module } from "@nestjs/common"
import { TypeOrmExModule } from "src/common/typeorm-ex.module"
import { ServerController } from "src/modules/server/controllers/server.controller"
import { ServerRepository } from "src/modules/server/repositories/server.repository"
import { SessionRepository } from "src/modules/server/repositories/session.repository"
import { sessionLogRepository } from "src/modules/server/repositories/sessionLog.repository"
import { ServerService } from "src/modules/server/services/server.service"
import { SessionService } from "src/modules/server/services/session.service"
import { SSHService } from "src/modules/server/services/ssh.service"

@Module({
	controllers: [ServerController],
	imports: [TypeOrmExModule.forFeature([ServerRepository, SessionRepository, sessionLogRepository])],
	providers: [ServerService, SSHService, SessionService],
})
export class ServerModule {}
