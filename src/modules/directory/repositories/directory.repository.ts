import { BaseRepository } from "src/common/base/base.repository"
import { EntityRepository } from "src/common/decorators/typeorm-ex.decorator"
import { Directory } from "src/modules/directory/entities/directory.entity"

@EntityRepository(Directory)
export class DirectoryRepository extends BaseRepository<Directory> {}
