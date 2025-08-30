import { BaseEntity } from "src/common/base/base.entity";
import {
  IsReferenceField,
  IsStringField,
} from "src/common/decorators/validation.decorator";
import { Column } from "typeorm";

export class Code {
  @IsStringField()
  content!: string;
}

export class PlayBook extends BaseEntity {
  @Column()
  name!: string;

  @Column()
  description!: string;

  @IsReferenceField()
  @Column("jsonb", { default: {} })
  content!: Code;
}
