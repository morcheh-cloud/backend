import { applyDecorators, UseInterceptors } from "@nestjs/common"
import { ClassConstructor, ClassTransformOptions } from "class-transformer"
import { CustomSerializerInterceptor } from "src/common/interceptors/serializer.interceptor"

export const StandardSerializer = (
	type: ClassConstructor<unknown>,
	options?: ClassTransformOptions,
	serialize?: boolean,
) => {
	return applyDecorators(
		UseInterceptors(new CustomSerializerInterceptor(type, options, serialize)),
	)
}
