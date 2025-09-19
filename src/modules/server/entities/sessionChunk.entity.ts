import { BaseEntityWithoutSoftDelete } from "src/common/base/base.entity"
import { Session } from "src/modules/server/entities/session.entity"
import { Entity, ManyToOne } from "typeorm"

@Entity()
export class SessionChunks extends BaseEntityWithoutSoftDelete {
	@ManyToOne(() => Session, { nullable: false })
	session?: Session
}
