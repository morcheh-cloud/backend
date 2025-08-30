import { EntityRepository } from "src/common/decorators/typeorm-ex.decorator";
import { PlayBook } from "src/modules/ansible/entities/playbooks.entity";
import { Repository } from "typeorm";

@EntityRepository(PlayBook)
export class PlaybookRepository extends Repository<PlayBook> {}
