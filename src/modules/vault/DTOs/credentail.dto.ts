import {
  IsDateField,
  IsNumberField,
  IsStringField,
} from "src/common/decorators/validation.decorator";

export class SaveCredentialPayload {
  @IsNumberField()
  serverId?: number;

  @IsNumberField()
  accountId?: number;

  @IsStringField()
  username?: string;

  @IsStringField()
  password?: string;

  @IsStringField()
  token?: string;

  @IsStringField()
  description?: string;

  @IsDateField()
  expiredAt?: Date;
}
