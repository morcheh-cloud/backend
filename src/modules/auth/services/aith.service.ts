import { Injectable } from "@nestjs/common";
import type { JwtService } from "@nestjs/jwt";

@Injectable()
export class AuthService {
  constructor(private jwtService: JwtService) {}

  async signIn(username: string, pass: string) {
    const payload = { pass, username };
    const access_token = await this.jwtService.signAsync(payload);

    return {
      access_token,
    };
  }
}
