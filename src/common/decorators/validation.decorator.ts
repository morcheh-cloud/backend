import { ApiProperty } from "@nestjs/swagger"
import { Expose, Transform, Type } from "class-transformer"
import {
	Allow,
	IsArray,
	IsBoolean,
	IsDate,
	IsInt,
	IsJSON,
	IsNumber,
	IsOptional,
	IsString,
	IsUUID,
	Matches,
	ValidateNested,
} from "class-validator"
import { EnsureIsArray } from "src/lib/utils"

export const RelationalFieldMetaDataKey = "RelationalFieldMetaDataKey"

export interface relationalFieldMetaData {
	property: string
	entity: string
	isArray?: boolean
	checkPermission?: boolean
	checkPermissionStrategy?: "host"
}

function getPropMetaData(
	params: { type?: object; isArray?: boolean },
	target: object,
	propertyKey: string,
): { propertyType: object; type: object; isArray: boolean } {
	const propertyType = Reflect.getMetadata("design:type", target, propertyKey)

	const isArray = params?.isArray || propertyType?.name === "Array"
	const type = params?.type || propertyType

	return { isArray, propertyType, type }
}

interface CommonDecoratorParam {
	type?: object
	isArray?: boolean
	required?: boolean
}

function isPlainFunction(fn: unknown): boolean {
	return (
		typeof fn === "function" &&
		!/^class\s/.test(Function.prototype.toString.call(fn))
	)
}

export function IsReferenceField(params?: {
	type?: object
	isArray?: boolean
	required?: boolean
}) {
	return (target: object, propertyKey: string) => {
		const { isArray, type } = getPropMetaData(params || {}, target, propertyKey)
		const required = params?.required ?? false

		const isFunc = isPlainFunction(type)
		const t: Function | object = isFunc ? type : () => type

		ApiProperty({ isArray, required, type: type as any })(target, propertyKey)
		Type(t as any)(target, propertyKey)
		Expose()(target, propertyKey)

		if (isArray) {
			IsArray()(target, propertyKey)
			ValidateNested()(target, propertyKey)
		}

		if (!required) {
			IsOptional()(target, propertyKey)
		}
	}
}

export function IsStringField(params?: {
	isArray?: boolean
	required?: boolean
}) {
	return (target: object, propertyKey: string) => {
		params ||= {}
		params.required = params.required ?? false
		const { isArray } = getPropMetaData(params, target, propertyKey)

		ApiProperty({ isArray, required: params.required, type: String })(
			target,
			propertyKey,
		)
		IsString({ each: isArray })(target, propertyKey)
		Type(() => String)(target, propertyKey)
		// IsNotEmpty({ each: isArray })(target, propertyKey);
		Expose()(target, propertyKey)

		if (!params?.required) {
			IsOptional()(target, propertyKey)
		}
	}
}

export function IsRegExpField(
	pattern: RegExp,
	params?: { isArray?: boolean; required?: boolean },
) {
	return (target: object, propertyKey: string): void => {
		params ||= {}
		params.required = params.required ?? false

		const { isArray } = getPropMetaData(params, target, propertyKey)

		ApiProperty({ isArray, required: params.required, type: String })(
			target,
			propertyKey,
		)
		Matches(pattern, { each: isArray })(target, propertyKey)
		Expose()(target, propertyKey)

		if (!params?.required) {
			IsOptional()(target, propertyKey)
		}
	}
}

export function IsNumberField(params?: {
	type?: object
	isArray?: boolean
	required?: boolean
}) {
	return (target: object, propertyKey: string) => {
		params ||= {}
		params.required = params.required ?? false

		const { isArray } = getPropMetaData(params, target, propertyKey)

		ApiProperty({ isArray, required: params.required, type: Number })(
			target,
			propertyKey,
		)
		IsNumber({}, { each: isArray })(target, propertyKey)
		Type(() => Number)(target, propertyKey)
		// IsNotEmpty({ each: isArray })(target, propertyKey);
		Expose()(target, propertyKey)

		if (!params?.required) {
			IsOptional()(target, propertyKey)
		}
	}
}
const optionalBooleanMapper = new Map([
	["undefined", undefined],
	["true", true],
	["false", false],
])

export function IsBooleanField(params?: {
	type?: object
	isArray?: boolean
	required?: boolean
}) {
	return (target: object, propertyKey: string) => {
		params ||= {}
		params.required = params.required ?? false
		const { isArray } = getPropMetaData(params, target, propertyKey)

		Expose()(target, propertyKey)
		ApiProperty({ isArray, required: params.required, type: Boolean })(
			target,
			propertyKey,
		)
		IsBoolean({ each: isArray })(target, propertyKey)
		Transform(({ value }) => {
			if (typeof value === "string") {
				return optionalBooleanMapper.get(value)
			} else {
				return value
			}
		})(target, propertyKey)

		if (!params?.required) {
			IsOptional()(target, propertyKey)
		}
	}
}

export function IsDateField(params?: {
	isArray?: boolean
	required?: boolean
}) {
	return (target: object, propertyKey: string) => {
		params ||= {}
		params.required = params.required ?? false
		const { isArray } = getPropMetaData(params, target, propertyKey)

		ApiProperty({ isArray, required: params.required, type: Date })(
			target,
			propertyKey,
		)
		IsDate({ each: isArray })(target, propertyKey)
		Type(() => Date)(target, propertyKey)
		// IsNotEmpty({ each: isArray })(target, propertyKey);
		Expose()(target, propertyKey)

		if (!params?.required) {
			IsOptional()(target, propertyKey)
		}
	}
}

interface IEnumField {
	isArray?: boolean
	required?: boolean
}

export function IsEnumField(enumObj: object, params: IEnumField = {}) {
	return (target: object, propertyKey: string): void => {
		const { isArray } = getPropMetaData(params, target, propertyKey)

		const required = params?.required ?? false

		ApiProperty({
			enum: enumObj,
			isArray,
			required,
			type: "string",
		})(target, propertyKey)

		Transform(({ value }) => {
			if (isArray) {
				return EnsureIsArray(value)
			} else {
				return value
			}
		})(target, propertyKey)

		Expose()(target, propertyKey)

		if (!required) {
			IsOptional()(target, propertyKey)
		}
	}
}

export function IsPrimaryKeyField(params?: CommonDecoratorParam) {
	return (target: object, propertyKey: string) => {
		params ||= {}
		params.required = params.required ?? false

		const { isArray } = getPropMetaData(params, target, propertyKey)

		if (!params?.required) {
			IsOptional()(target, propertyKey)
		}

		IsInt({ each: isArray })(target, propertyKey)
		Type(() => Number)(target, propertyKey)
		Expose()(target, propertyKey)
		ApiProperty({ isArray, required: params?.required, type: Number })(
			target,
			propertyKey,
		)
	}
}

export function IsTimeField(params?: CommonDecoratorParam) {
	return (target: object, propertyKey: string): void => {
		params ||= {}
		params.required = params.required ?? false

		const pattern = /^(0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]$/

		const { isArray } = getPropMetaData(params, target, propertyKey)
		ApiProperty({
			isArray,
			pattern: String(pattern),
			required: params.required,
			type: "string",
		})(target, propertyKey)
		Matches(pattern)
		Expose()(target, propertyKey)

		if (!params?.required) {
			IsOptional()(target, propertyKey)
		}
	}
}

export function IsJSONField(params?: {
	isArray?: boolean
	required?: boolean
}) {
	return (target: object, propertyKey: string): void => {
		params ||= {}
		params.required = params.required ?? false

		const { isArray } = getPropMetaData(params, target, propertyKey)

		ApiProperty({ isArray, required: params.required, type: "null" })(
			target,
			propertyKey,
		)
		Allow()(target, propertyKey)
		IsJSON({ each: isArray })(target, propertyKey)
		Expose()(target, propertyKey)

		if (!params?.required) {
			IsOptional()(target, propertyKey)
		}
	}
}

export function IsObjectField(params?: {
	isArray?: boolean
	required?: boolean
}) {
	return (target: object, propertyKey: string): void => {
		params ||= {}
		const { isArray } = getPropMetaData(params, target, propertyKey)

		IsOptional()(target, propertyKey)
		ApiProperty({
			isArray,
			required: params.required ?? false,
			type: "null",
		})(target, propertyKey)
		// IsObject({ each: isArray })(target, propertyKey);
		Allow({ always: true })(target, propertyKey)
		Expose()(target, propertyKey)
	}
}

// class MediaDTO {
//   @IsNumberField()
//   id!: number;

//   @IsStringField()
//   url?: string;

//   @IsStringField()
//   fileName?: string;

//   @IsStringField()
//   ext?: string;

//   @IsNumberField()
//   size?: number; // in kb

//   @IsStringField()
//   mimetype?: string;

//   @IsStringField()
//   description!: string;
// }

// export function IsMediaField(params?: {
//   isArray?: boolean;
//   required?: boolean;
// }) {
//   return (target: object, propertyKey: string) => {
//     const { isArray } = getPropMetaData(params, target, propertyKey);

//     ApiProperty({ isArray, required: false, type: MediaDTO })(
//       target,
//       propertyKey
//     );
//     // IsObject({ each: isArray })(target, propertyKey);
//     Type(() => MediaDTO)(target, propertyKey);
//     Expose()(target, propertyKey);
//     IsOptional()(target, propertyKey);
//   };
// }

export function IsUUIDField(params?: {
	version?: "3" | "4" | "5" | 3 | 4 | 5
	isArray?: boolean
	required?: boolean
}) {
	return (target: object, propertyKey: string): void => {
		params ||= {}
		params.required = params.required ?? false
		params.version = params.version ?? "4"

		const { isArray } = getPropMetaData(params, target, propertyKey)

		ApiProperty({ isArray, required: params.required, type: String })(
			target,
			propertyKey,
		)
		IsUUID(params.version, { each: isArray })(target, propertyKey)
		Expose()(target, propertyKey)

		if (!params?.required) {
			IsOptional()(target, propertyKey)
		}
	}
}
