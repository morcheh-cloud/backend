import { BaseRepository } from "src/common/base/base.repository"
import { EntityRepository } from "src/common/decorators/typeorm-ex.decorator"
import { Workspace } from "src/modules/workspace/entities/workspace.entity"

@EntityRepository(Workspace)
export class WorkspaceRepository extends BaseRepository<Workspace> {}
