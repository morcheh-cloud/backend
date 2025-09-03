import {
	HttpCode,
	HttpStatus,
	Logger,
	RequestMethod,
	UsePipes,
	Version,
} from "@nestjs/common"
import { ApiBody } from "@nestjs/swagger"
import { ClassTransformOptions } from "class-transformer"
import { CreateEntityModelPipe } from "src/common/pipes/createEntityModel.pipe"
import { CustomApiOperation } from "./customApiOperation.decorator"
import { StandardSerializer } from "./serializer.decorator"
import { StandardApiResponse } from "./standardApiRes.decorator"

interface StandardApiInterface {
	// biome-ignore lint/suspicious/noExplicitAny: <explanation>
	type?: any
	resTypeOption?: ClassTransformOptions
	statusCode?: HttpStatus
	description?: string
	isArray?: boolean
	deprecated?: boolean
	operationId?: string
	auth?: boolean
	serialize?: boolean
	summary?: string
	uploadFile?: boolean
	isStandard?: boolean
	ignoreWarning?: boolean
	version?: number | number[]
	body?: {
		type?: unknown
		isArray?: boolean
	}
}

const logger = new Logger()
export const GlobalHandlerName: string[] = []

function getMetaData(target: any, propertyKey: string, descriptor: any) {
	return {
		constructorName: target.constructor.name,
		method: Reflect.getMetadata("method", descriptor.value),
		name: propertyKey,
		params: Reflect.getMetadata("design:paramtypes", target, "getHostSitMap"),
		return: Reflect.getMetadata("design:returntype", target, propertyKey),
	}
}

const getStatusCode = (code: any) => {
	let statusCode: number
	switch (code) {
		case [RequestMethod.DELETE, RequestMethod.PUT, RequestMethod.GET].includes(
			code,
		):
			statusCode = 200
			break
		case code === RequestMethod.POST:
			statusCode = 201
			break
		default:
			statusCode = 200
	}

	return statusCode
}

function defineDecorators(
	params: StandardApiInterface = {},
	target: any,
	propertyKey: any,
	descriptor: any,
): any[] {
	let { statusCode: status, version, isArray, type } = params

	const {
		description,
		deprecated,
		operationId,
		summary,
		isStandard = true,
		ignoreWarning,
		body,
		resTypeOption,
		serialize,
	} = params

	isArray = type?.constructor?.name === "Array"
	type = isArray ? type?.[0] : type

	const metaData = getMetaData(target, propertyKey, descriptor)

	version ||= 1
	const convertedVersion =
		typeof version === "number"
			? String(version)
			: version.map((i) => String(i))

	let decorators = [
		HttpCode(status as number),
		UsePipes(new CreateEntityModelPipe()),
		Version(convertedVersion),
		CustomApiOperation({
			...(deprecated !== undefined && { deprecated }),
			...(operationId !== undefined && { operationId }),
			...(summary !== undefined && { summary }),
		}),
	]

	if (metaData.method === undefined && ignoreWarning !== false && !status) {
		logger.warn(
			`Use Standard Api upper than Method Decorators ( @GET , @POST , ...) ${metaData.name}-${metaData.constructorName}`,
			"INIT API",
		)
	}
	status ||= getStatusCode(metaData.method)

	if (isStandard !== false && type) {
		decorators = [
			...decorators,
			StandardSerializer(type, resTypeOption || {}, serialize),
			StandardApiResponse({
				description: description || "",
				isArray,
				status,
				type,
			}),
		]
	}

	if (body?.type) {
		body.isArray ||= Array.isArray(body.type)
		if (body.isArray && Array.isArray(body.type)) {
			body.type = body.type[0]
		}

		decorators = [
			...decorators,
			ApiBody({ isArray: body?.isArray, type: body?.type as any }),
		]
	}

	return decorators
}

export function StandardApi(params?: StandardApiInterface) {
	return (target: any, propertyKey: string, descriptor: any) => {
		const decorators = defineDecorators(params, target, propertyKey, descriptor)
		for (const decorator of decorators) {
			if (target instanceof Function && !descriptor) {
				decorator(target)
				continue
			}
			decorator(target, propertyKey, descriptor)
		}
	}
}
