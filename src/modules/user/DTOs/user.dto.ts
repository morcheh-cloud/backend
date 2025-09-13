import { IsReferenceField } from "src/common/decorators/validation.decorator";
import { User } from "src/modules/user/entities/user.entity";
import { Workspace } from "src/modules/workspace/entities/workspace.entity";

export class UserModel extends User {
  @IsReferenceField({ type: Workspace })
  workspaces?: Workspace[];
}
