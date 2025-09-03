import { BaseRepository } from "src/common/base/base.repository"
import { EntityRepository } from "src/common/decorators/typeorm-ex.decorator"
import { PlayBook } from "src/modules/ansible/entities/playbooks.entity"

@EntityRepository(PlayBook)
export class PlaybookRepository extends BaseRepository<PlayBook> {}
