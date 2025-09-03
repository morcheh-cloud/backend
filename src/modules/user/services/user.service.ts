import { Injectable } from "@nestjs/common";
import { UserRepository } from "src/modules/user/repositories/user.repository";

@Injectable()
export class UserService {
  constructor(private userRepository: UserRepository) {}

  async getContextUserById(id: number) {
    return this.userRepository.findOneOrFail({
      where: { id },
    });
  }
}
