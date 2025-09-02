import { BaseRepository } from "src/common/base/base.repository";
import { EntityRepository } from "src/common/decorators/typeorm-ex.decorator";
import { User } from "src/modules/user/entities/user.entity";

@EntityRepository(User)
export class UserRepository extends BaseRepository<User> {}
