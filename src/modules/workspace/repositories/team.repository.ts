import { BaseRepository } from "src/common/base/base.repository"
import { EntityRepository } from "src/common/decorators/typeorm-ex.decorator"
import { Team } from "src/modules/workspace/entities/team.entity"

@EntityRepository(Team)
export class TeamRepository extends BaseRepository<Team> {}
