import { Controller, Post } from "@nestjs/common";
import { AnsibleService } from "src/modules/ansible/services/ansible.service";

@Controller("ansible")
export class AnsibleController {
  constructor(private ansibleService: AnsibleService) {}

  @Post("sync")
  async syncAnsible() {
    await this.ansibleService.sync();
    return {
      success: true,
    };
  }
}
