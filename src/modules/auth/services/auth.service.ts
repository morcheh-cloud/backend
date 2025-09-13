import { ForbiddenException, Injectable } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { compare, genSalt, hash } from "bcrypt";
import { JWTPayload, RegisterPayload } from "src/modules/auth/DTOs/auth.dto";
import { UserRepository } from "src/modules/user/repositories/user.repository";

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private userRepository: UserRepository
  ) {}

  async checkRegisterNewUserIsLocked(): Promise<boolean> {
    const usersCount = await this.userRepository.count({ take: 1 });
    const isLocked = usersCount !== 0;
    return isLocked;
  }

  private async hashPassword(password: string): Promise<string> {
    const salt = await genSalt(10);
    return hash(password, salt);
  }

  private async verifyPassword(
    password: string,
    hashedPassword: string
  ): Promise<boolean> {
    return compare(password, hashedPassword);
  }

  async login(email: string, pass: string) {
    const user = await this.userRepository.findOne({
      where: { email },
    });

    if (!user) {
      throw new ForbiddenException("Access Denied");
    }

    const passwordMatches = await this.verifyPassword(pass, user.password);
    if (!passwordMatches) {
      throw new ForbiddenException("Access Denied");
    }

    const payload: JWTPayload = { email: user.email, id: user.id };
    const access_token = await this.jwtService.signAsync(payload);

    return {
      access_token,
      payload,
    };
  }

  async register(payload: RegisterPayload) {
    const isLocked = await this.checkRegisterNewUserIsLocked();
    if (isLocked) {
      throw new ForbiddenException("User registration is locked");
    }

    const isExist = await this.userRepository.findOne({
      where: { email: payload.email },
    });
    if (isExist) {
      throw new ForbiddenException("User already exists");
    }

    const { password, email, fullName } = payload;

    const hashedPassword = await this.hashPassword(password);

    const usersCount = await this.userRepository.count({ take: 1 });
    const isAdmin = usersCount === 0;

    const user = await this.userRepository.createAndSave({
      email,
      fullName,
      isAdmin,
      password: hashedPassword,
    });

    const { access_token } = await this.login(email, password);

    return {
      access_token,
      user,
    };
  }

  async whoAmI(userId: string) {
    const user = await this.userRepository.findOne({
      relations: {
        workspaces: {},
      },
      where: {
        id: userId,
      },
    });

    return user;
  }
}
