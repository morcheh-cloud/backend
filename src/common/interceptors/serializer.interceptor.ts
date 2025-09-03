import {
	CallHandler,
	ExecutionContext,
	Injectable,
	NestInterceptor,
	NotFoundException,
} from "@nestjs/common"
import * as classTransformOptionsInterface from "@nestjs/common/interfaces/external/class-transform-options.interface"
import * as classTransformer from "class-transformer"
import { isArray, isEmpty } from "lodash"
import { map } from "rxjs/operators"

@Injectable()
export class CustomSerializerInterceptor implements NestInterceptor {
	type: unknown
	customOptions?: classTransformOptionsInterface.ClassTransformOptions
	serialize: boolean
	TypeOfData = "type"

	private defaultOptions: classTransformOptionsInterface.ClassTransformOptions =
		{
			enableCircularCheck: true, // circle check fot nested class
			enableImplicitConversion: true, // check type
			excludeExtraneousValues: true, // strip unexposed property
			strategy: "excludeAll", // default strategy to strip all field expect exposed property
		}

	constructor(
		type: classTransformer.ClassConstructor<unknown>,
		options?: classTransformOptionsInterface.ClassTransformOptions,
		serialize?: boolean,
	) {
		this.type = type
		this.customOptions = options || {}
		this.serialize = serialize ?? true
	}

	private serializeResponse(
		type: classTransformer.ClassConstructor<unknown>,
		payload: unknown | unknown[],
		options: classTransformOptionsInterface.ClassTransformOptions,
	): unknown | unknown[] {
		//

		let data = classTransformer.plainToInstance(type, payload, {
			...options,
		})

		if (isArray(data)) {
			data = data.filter((item) => !isEmpty(item))
		}

		return data
	}

	intercept(_: ExecutionContext, next: CallHandler) {
		return next.handle().pipe(
			map(async (data: unknown) => {
				data = await data

				if (!data) {
					throw new NotFoundException()
				}

				if (this.serialize) {
					const result = this.serializeResponse(this.type as any, data, {
						...this.defaultOptions,
						...this.customOptions,
					})

					return result
				} else {
					return data
				}
			}),
		)
	}
}
