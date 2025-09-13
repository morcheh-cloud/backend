import { IsStringField } from "src/common/decorators/validation.decorator";
import { Workspace } from "src/modules/workspace/entities/workspace.entity";

export class CreateWorkSpacePayload {
  @IsStringField({ required: true })
  name!: string;

  @IsStringField({ required: false })
  descriptions?: string;

  @IsStringField({ required: true })
  timezone!: string;
}

export class WorkSpaceModel extends Workspace {}
