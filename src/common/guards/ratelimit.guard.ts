import { Injectable } from "@nestjs/common"
import { ThrottlerGuard, type ThrottlerRequest } from "@nestjs/throttler"
import type { Request } from "express"
import { IP_HEADER_NAME } from "src/config/app.config"

@Injectable()
export class RatelimitGuard extends ThrottlerGuard {
	protected override async getTracker(req: Request): Promise<string> {
		const headers = req.headers
		const ip =
			(headers[IP_HEADER_NAME] as string) ||
			(headers["ar-real-ip"] as string) ||
			(headers["cf-connecting-ip"] as string) ||
			req.ip

		return ip || "unknown"
	}

	protected override async handleRequest(
		requestProps: ThrottlerRequest,
	): Promise<boolean> {
		const req = requestProps.context.switchToHttp().getRequest<Request>()
		const ip = await this.getTracker(req)

		// skip localhost
		if (ip === "127.0.0.1" || ip === "::1") {
			return true
		}

		return await super.handleRequest(requestProps)
	}
}
