import {
  type CanActivate,
  type ExecutionContext,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { JwtService } from "@nestjs/jwt";
import { InjectDataSource } from "@nestjs/typeorm";
import type { Request } from "express";
import { omit } from "lodash";
import { IS_PUBLIC_KEY } from "src/common/decorators/isPublic.decorator";
import { JWT_CONFIG } from "src/config/app.config";
import { JWTPayload } from "src/modules/auth/DTOs/auth.dto";
import { User } from "src/modules/user/entities/user.entity";
import { Workspace } from "src/modules/workspace/entities/workspace.entity";
import { DataSource } from "typeorm";

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private reflector: Reflector,
    @InjectDataSource()
    private datasource: DataSource
  ) {}

  private async getContextUserById(id: number): Promise<User | null> {
    let user = await this.datasource.getRepository(User).findOne({
      where: { id },
    });

    user = omit(user, ["password"]) as User;

    return user;
  }

  private async getContextWorkspaceById(workspaceId: number, userId: number) {
    const workspace = await this.datasource.getRepository(Workspace).findOne({
      where: [
        {
          id: workspaceId,
          owner: {
            id: userId,
          },
        },
        // {
        //   id: workspaceId,
        //   permission: {
        //     user: {
        //       id: userId,
        //     },
        //   },
        // },
      ],
    });

    return workspace;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(" ") ?? [];
    return type === "Bearer" ? token : undefined;
  }

  private extractApiKeyFromHeader(request: Request): string | undefined {
    return request.headers["x-api-key"] as string | undefined;
  }

  private extractWorkspaceId(request: Request): number | undefined {
    const workspaceId =
      request.query["workspaceId"] || request.headers["workspaceId"];

    return Number(workspaceId);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    let user: User | null;

    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest();

    const apiKey = this.extractApiKeyFromHeader(request);
    if (apiKey) {
      return true;
    }

    const jwtToken = this.extractTokenFromHeader(request);
    if (!jwtToken) {
      throw new UnauthorizedException("No token provided");
    }

    try {
      const payload: JWTPayload = await this.jwtService.verifyAsync(jwtToken, {
        secret: JWT_CONFIG.secret,
      });

      user = await this.getContextUserById(payload.id);
      if (!user) {
        throw new UnauthorizedException("User not found");
      }
      request["user"] = user;

      // Attach user information to the request object
    } catch {
      throw new UnauthorizedException(
        "Your session has expired. Please log in again."
      );
    }

    const workspaceId = this.extractWorkspaceId(request);

    if (workspaceId && !user?.id) {
      throw new NotFoundException("User not found");
    }

    if (workspaceId) {
      const workspace = await this.getContextWorkspaceById(
        workspaceId,
        user.id
      );

      if (!workspace) {
        throw new NotFoundException("Workspace not found");
      }

      request["workspace"] = workspace;
    }

    return true;
  }
}
