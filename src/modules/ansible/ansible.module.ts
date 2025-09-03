import { Module } from "@nestjs/common"
import { TypeOrmExModule } from "src/common/typeorm-ex.module"
import { AnsibleController } from "src/modules/ansible/controllers/playbook.controller"
import { AnsibleGateway } from "src/modules/ansible/gateways/ansible.gateway"
import { PlaybookRepository } from "src/modules/ansible/repositories/playbook.repository"
import { AnsibleService } from "src/modules/ansible/services/ansible.service"
import { PlaybookService } from "src/modules/ansible/services/playbook.service"

@Module({
	controllers: [AnsibleController],
	imports: [TypeOrmExModule.forFeature([PlaybookRepository])],
	providers: [PlaybookService, AnsibleService, AnsibleGateway],
})
export class AnsibleModule {}
