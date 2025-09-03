import type { ThrottlerModuleOptions } from "@nestjs/throttler"

export const RATE_LIMIT_CONFIG: ThrottlerModuleOptions = [
	{
		limit: 3,
		name: "short",
		ttl: 1000,
	},
	{
		limit: 20,
		name: "medium",
		ttl: 10000,
	},
	{
		limit: 100,
		name: "long",
		ttl: 60000,
	},
]
