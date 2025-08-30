import { Exclude } from "class-transformer";
import { BaseEntity } from "src/common/base/base.entity";
import {
  IsEnumField,
  IsStringField,
} from "src/common/decorators/validation.decorator";
import { Column, Entity } from "typeorm";

export enum Role {
  USER = "user",
  ADMIN = "admin",
}

@Entity()
export class User extends BaseEntity {
  @IsEnumField(Role)
  @Column({ enum: Role, type: "enum" })
  role!: Role;

  @IsStringField()
  @Column()
  fullName!: string;

  @IsStringField()
  @Column({ unique: true })
  email!: string;

  @Exclude()
  @Column()
  password!: string;
}
