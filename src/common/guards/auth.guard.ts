import {
	type CanActivate,
	type ExecutionContext,
	Injectable,
	UnauthorizedException,
} from "@nestjs/common"
import type { Reflector } from "@nestjs/core"
import type { JwtService } from "@nestjs/jwt"
import type { Request } from "express"
import { IS_PUBLIC_KEY } from "src/common/decorators/isPublic.decorator"
import { JWT_CONFIG } from "src/config/app.config"

@Injectable()
export class AuthGuard implements CanActivate {
	constructor(
		private jwtService: JwtService,
		private reflector: Reflector,
	) {}

	private extractTokenFromHeader(request: Request): string | undefined {
		const [type, token] = request.headers.authorization?.split(" ") ?? []
		return type === "Bearer" ? token : undefined
	}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
			context.getHandler(),
			context.getClass(),
		])
		if (isPublic) {
			return true
		}

		const request = context.switchToHttp().getRequest()
		const token = this.extractTokenFromHeader(request)
		if (!token) {
			throw new UnauthorizedException("No token provided")
		}

		try {
			const payload = await this.jwtService.verifyAsync(token, {
				secret: JWT_CONFIG.secret,
			})
			request["user"] = payload
		} catch {
			throw new UnauthorizedException(
				"Your session has expired. Please log in again.",
			)
		}
		return true
	}
}
