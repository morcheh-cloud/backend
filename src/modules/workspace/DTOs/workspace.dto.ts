import { IsStringField } from "src/common/decorators/validation.decorator";

export class CreateWorkSpacePayload {
  @IsStringField({ required: true })
  name!: string;

  @IsStringField({ required: false })
  descriptions?: string;

  @IsStringField({ required: true })
  timezone!: string;
}
