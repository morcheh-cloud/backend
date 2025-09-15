import type { User } from "src/modules/user/entities/user.entity"
import type { Workspace } from "src/modules/workspace/entities/workspace.entity"

declare global {
	namespace Express {
		interface Request {
			user?: User // or whatever shape your user has
			workspace?: Workspace
		}
	}
}
