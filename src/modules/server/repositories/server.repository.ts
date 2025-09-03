import { BaseRepository } from "src/common/base/base.repository"
import { EntityRepository } from "src/common/decorators/typeorm-ex.decorator"
import { Server } from "src/modules/server/entities/server.entity"

@EntityRepository(Server)
export class ServerRepository extends BaseRepository<Server> {}
