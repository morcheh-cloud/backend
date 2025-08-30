import { IsNumberField } from "src/common/decorators/validation.decorator";
import { PrimaryGeneratedColumn } from "typeorm/browser/decorator/columns/PrimaryGeneratedColumn.js";

export class BaseEntity {
  @IsNumberField()
  @PrimaryGeneratedColumn()
  id!: number;
}
