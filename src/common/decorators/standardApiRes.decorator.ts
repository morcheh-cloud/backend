import { applyDecorators } from "@nestjs/common"
import { ApiExtraModels, ApiResponse } from "@nestjs/swagger"

interface IStandardApiResponse {
	// biome-ignore lint/suspicious/noExplicitAny: <explanation>
	type: any
	isArray: boolean
	description: string
	status: number
}

export const StandardApiResponse = ({
	type,
	isArray,
	description,
	status,
}: IStandardApiResponse) => {
	return applyDecorators(
		ApiExtraModels(type),
		ApiResponse({
			description,
			isArray,
			status,
			type,
		}),
	)
}
