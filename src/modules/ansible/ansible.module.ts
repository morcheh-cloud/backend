import { Module } from "@nestjs/common";
import { TypeOrmExModule } from "src/common/typeorm-ex.module";
import { AnsibleController } from "src/modules/ansible/controllers/ansible.controller";
import { PlaybookRepository } from "src/modules/ansible/repositories/ansible.repository";
import { AnsibleService } from "src/modules/ansible/services/ansible.service";

@Module({
  controllers: [AnsibleController],
  imports: [TypeOrmExModule.forFeature([PlaybookRepository])],
  providers: [AnsibleService],
})
export class AnsibleModule {}
