import { IsReferenceField } from "src/common/decorators/validation.decorator";
import { User } from "src/modules/user/entities/user.entity";
import { WorkSpaceModel } from "src/modules/workspace/DTOs/workspace.dto";
import { Workspace } from "src/modules/workspace/entities/workspace.entity";

export class UserModel extends User {
  @IsReferenceField({ type: WorkSpaceModel })
  workspaces?: Workspace[];
}
