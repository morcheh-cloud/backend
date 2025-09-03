import { Body, Post } from "@nestjs/common";
import { BasicController } from "src/common/decorators/basicController.decorator";
import { IsPublicApi } from "src/common/decorators/isPublic.decorator";
import { StandardApi } from "src/common/decorators/standard-api.decorator";
import {
  LoginModel,
  LoginPayload,
  RegisterModel,
  RegisterPayload,
} from "src/modules/auth/DTOs/auth.dto";
import { AuthService } from "src/modules/auth/services/auth.service";

@BasicController("auth")
export class AuthController {
  constructor(private authService: AuthService) {}

  @StandardApi({ type: RegisterModel })
  @Post("register")
  async register(@Body() body: RegisterPayload): Promise<RegisterModel> {
    const { access_token, user } = await this.authService.register(body);

    return { access_token, data: { email: user.email, id: user.id } };
  }

  @IsPublicApi()
  @StandardApi({ type: LoginModel })
  @Post("login")
  async login(@Body() body: LoginPayload): Promise<LoginModel> {
    const { access_token, payload } = await this.authService.login(
      body.email,
      body.password
    );

    return { access_token, data: payload };
  }
}
