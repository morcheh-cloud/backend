import { BaseEntity } from "src/common/base/base.entity";
import {
  IsBooleanField,
  IsStringField,
} from "src/common/decorators/validation.decorator";
import { Server } from "src/modules/server/entities/server.entity";
import { Column, Entity, ManyToOne, OneToMany } from "typeorm";

@Entity()
export class Directory extends BaseEntity {
  @ManyToOne(() => Directory, (d) => d.children, { onDelete: "CASCADE" })
  parent?: Directory;

  @OneToMany(() => Directory, (directory) => directory.parent, {
    onDelete: "CASCADE",
  })
  children?: Directory[];

  @OneToMany(() => Server, (server) => server.directory)
  servers?: Server[];

  @IsStringField()
  @Column()
  name!: string;

  @IsBooleanField()
  @Column({ default: true })
  isDeletable!: boolean;

  @IsBooleanField()
  @Column({ default: true })
  isEditable!: boolean;

  @IsBooleanField()
  @Column({ default: true })
  isVisible!: boolean;

  @IsBooleanField()
  @Column({ default: false })
  isLocked!: boolean;

  @IsStringField()
  @Column({ nullable: true })
  icon?: string;
}
