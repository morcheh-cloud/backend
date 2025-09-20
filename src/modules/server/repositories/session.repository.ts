import { BaseRepository } from "src/common/base/base.repository"
import { EntityRepository } from "src/common/decorators/typeorm-ex.decorator"
import { Session } from "src/modules/server/entities/session.entity"

@EntityRepository(Session)
export class SessionRepository extends BaseRepository<Session> {}
