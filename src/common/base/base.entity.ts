import { IsNumberField } from "src/common/decorators/validation.decorator";
import {
  CreateDateColumn,
  DeleteDateColumn,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from "typeorm";

export class BaseEntityWithoutSoftDelete {
  @IsNumberField()
  @PrimaryGeneratedColumn()
  id!: number;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}

export class BaseEntity extends BaseEntityWithoutSoftDelete {
  @DeleteDateColumn()
  deletedAt?: Date;
}
