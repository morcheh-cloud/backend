import { ApiProperty } from '@nestjs/swagger';
import { Expose, Transform, Type } from 'class-transformer';
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
} from 'class-validator';
import { EnsureIsArray } from 'src/lib/utils';

export const RelationalFieldMetaDataKey = 'RelationalFieldMetaDataKey';

export interface relationalFieldMetaData {
  property: string;
  entity: string;
  isArray?: boolean;
  checkPermission?: boolean;
  checkPermissionStrategy?: 'host';
}

function getPropMetaData(
  params: { type?: any; isArray?: boolean; [k: string]: any },
  target: any,
  propertyKey: string,
): { propertyType: any; type: any; isArray: boolean } {
  const propertyType = Reflect.getMetadata('design:type', target, propertyKey);

  const isArray = params?.isArray || propertyType?.name === 'Array';
  const type = params?.type || propertyType;

  return { propertyType, type, isArray };
}

interface CommonDecoratorParam {
  type?: any;
  isArray?: boolean;
  required?: boolean;
}

function isPlainFunction(fn: unknown): boolean {
  return (
    typeof fn === 'function' &&
    !/^class\s/.test(Function.prototype.toString.call(fn))
  );
}

export function IsReferenceField(params?: {
  type?: any;
  isArray?: boolean;
  required?: boolean;
}) {
  return function (target: any, propertyKey: string): void {
    const { isArray, type } = getPropMetaData(params, target, propertyKey);
    const required = params?.required ?? false;

    const isFunc = isPlainFunction(type);
    const t = isFunc ? type : () => type;

    ApiProperty({ type, isArray, required })(target, propertyKey);
    Type(t)(target, propertyKey);
    Expose()(target, propertyKey);

    if (isArray) {
      IsArray()(target, propertyKey);
      ValidateNested()(target, propertyKey);
    }

    if (!required) {
      IsOptional()(target, propertyKey);
    }
  };
}

export function IsStringField(params?: {
  type?: any;
  isArray?: boolean;
  required?: boolean;
}) {
  return function (target: any, propertyKey: string): void {
    params ||= {};
    params.required = params.required ?? false;
    const { isArray } = getPropMetaData(params, target, propertyKey);

    ApiProperty({ type: String, required: params.required, isArray })(
      target,
      propertyKey,
    );
    IsString({ each: isArray })(target, propertyKey);
    Type(() => String)(target, propertyKey);
    // IsNotEmpty({ each: isArray })(target, propertyKey);
    Expose()(target, propertyKey);

    if (!params?.required) {
      IsOptional()(target, propertyKey);
    }
  };
}

export function IsRegExpField(
  pattern: RegExp,
  params?: { type?: any; isArray?: boolean; required?: boolean },
) {
  return function (target: any, propertyKey: string): void {
    params ||= {};
    params.required = params.required ?? false;

    const { isArray } = getPropMetaData(params, target, propertyKey);

    ApiProperty({ type: String, required: params.required, isArray })(
      target,
      propertyKey,
    );
    Matches(pattern, { each: isArray })(target, propertyKey);
    Expose()(target, propertyKey);

    if (!params?.required) {
      IsOptional()(target, propertyKey);
    }
  };
}

export function IsNumberField(params?: {
  type?: any;
  isArray?: boolean;
  required?: boolean;
}) {
  return function (target: any, propertyKey: string) {
    params ||= {};
    params.required = params.required ?? false;

    const { isArray } = getPropMetaData(params, target, propertyKey);

    ApiProperty({ type: Number, required: params.required, isArray })(
      target,
      propertyKey,
    );
    IsNumber({}, { each: isArray })(target, propertyKey);
    Type(() => Number)(target, propertyKey);
    // IsNotEmpty({ each: isArray })(target, propertyKey);
    Expose()(target, propertyKey);

    if (!params?.required) {
      IsOptional()(target, propertyKey);
    }
  };
}
const optionalBooleanMapper = new Map([
  ['undefined', undefined],
  ['true', true],
  ['false', false],
]);

export function IsBooleanField(params?: {
  type?: any;
  isArray?: boolean;
  required?: boolean;
}) {
  return function (target: any, propertyKey: string) {
    params ||= {};
    params.required = params.required ?? false;
    const { isArray } = getPropMetaData(params, target, propertyKey);

    Expose()(target, propertyKey);
    ApiProperty({ type: Boolean, required: params.required, isArray })(
      target,
      propertyKey,
    );
    IsBoolean({ each: isArray })(target, propertyKey);
    Transform(({ value }) => {
      if (typeof value === 'string') {
        return optionalBooleanMapper.get(value);
      } else {
        return value;
      }
    })(target, propertyKey);

    if (!params?.required) {
      IsOptional()(target, propertyKey);
    }
  };
}

export function IsDateField(params?: {
  type?: any;
  isArray?: boolean;
  required?: boolean;
}) {
  return function (target: any, propertyKey: string) {
    params ||= {};
    params.required = params.required ?? false;
    const { isArray } = getPropMetaData(params, target, propertyKey);

    ApiProperty({ type: Date, required: params.required, isArray })(
      target,
      propertyKey,
    );
    IsDate({ each: isArray })(target, propertyKey);
    Type(() => Date)(target, propertyKey);
    // IsNotEmpty({ each: isArray })(target, propertyKey);
    Expose()(target, propertyKey);

    if (!params?.required) {
      IsOptional()(target, propertyKey);
    }
  };
}

export function IsEnumField(params: {
  type: any;
  isArray?: boolean;
  required?: boolean;
}) {
  return function (target: any, propertyKey: string): void {
    const { isArray, type } = getPropMetaData(params, target, propertyKey);

    params ||= { type };
    params.required = params.required ?? false;

    ApiProperty({
      enum: type,
      type: 'string',
      required: params.required,
      isArray,
    })(target, propertyKey);
    // TODO: fix this
    // if (!isArray) {
    //   IsEnum(type, { each: isArray })(target, propertyKey);
    // }
    Transform(({ value }) => {
      if (isArray) {
        return EnsureIsArray(value);
      } else {
        return value;
      }
    })(target, propertyKey);
    Expose()(target, propertyKey);

    // if (!params?.required) {
    IsOptional()(target, propertyKey);
    // }
  };
}

export function IsPrimaryKeyField(params?: {
  type?: any;
  isArray?: boolean;
  required?: boolean;
  checkPermission?: boolean;
  checkPermissionStrategy?: 'host';
}): PropertyDecorator {
  return function (target: any, propertyKey: string): void {
    params ||= {};
    params.required = params.required ?? false;

    const { isArray, type } = getPropMetaData(params, target, propertyKey);

    if (!params?.required) {
      IsOptional()(target, propertyKey);
    }

    IsInt({ each: isArray })(target, propertyKey);
    Type(() => Number)(target, propertyKey);
    Expose()(target, propertyKey);
    ApiProperty({ required: params?.required, type: Number, isArray })(
      target,
      propertyKey,
    );

    let relationalFields: relationalFieldMetaData[] = Reflect.getMetadata(
      RelationalFieldMetaDataKey,
      target.constructor,
    );

    relationalFields ||= [];
    relationalFields.push({
      entity: type?.name,
      property: propertyKey,
      isArray,
      checkPermission: params.checkPermission,
      checkPermissionStrategy: params.checkPermissionStrategy,
    });

    Reflect.defineMetadata(
      RelationalFieldMetaDataKey,
      relationalFields,
      target.constructor,
    );
  };
}

export function IsTimeField(params?: CommonDecoratorParam) {
  return function (target: any, propertyKey: string): void {
    params ||= {};
    params.required = params.required ?? false;

    const pattern = /^(0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]$/;

    const { isArray } = getPropMetaData(params, target, propertyKey);
    ApiProperty({
      required: params.required,
      isArray,
      type: 'string',
      pattern: String(pattern),
    })(target, propertyKey);
    Matches(pattern);
    Expose()(target, propertyKey);

    if (!params?.required) {
      IsOptional()(target, propertyKey);
    }
  };
}

export function IsJSONField(params?: {
  type?: any;
  isArray?: boolean;
  required?: boolean;
}) {
  return function (target: any, propertyKey: string): void {
    params ||= {};
    params.required = params.required ?? false;

    const { isArray } = getPropMetaData(params, target, propertyKey);

    ApiProperty({ type: 'null', required: params.required, isArray })(
      target,
      propertyKey,
    );
    Allow()(target, propertyKey);
    IsJSON({ each: isArray })(target, propertyKey);
    Expose()(target, propertyKey);

    if (!params?.required) {
      IsOptional()(target, propertyKey);
    }
  };
}

export function IsObjectField(params?: {
  type?: any;
  isArray?: boolean;
  required?: boolean;
}) {
  return function (target: any, propertyKey: string): void {
    params ||= {};
    const { isArray } = getPropMetaData(params, target, propertyKey);

    IsOptional()(target, propertyKey);
    ApiProperty({
      type: 'null',
      required: params.required ?? false,
      isArray,
    })(target, propertyKey);
    // IsObject({ each: isArray })(target, propertyKey);
    Allow({ always: true })(target, propertyKey);
    Expose()(target, propertyKey);
  };
}

class MediaDTO {
  @IsNumberField()
  id: number;

  @IsStringField()
  url?: string;

  @IsStringField()
  fileName?: string;

  @IsStringField()
  ext?: string;

  @IsNumberField()
  size?: number; // in kb

  @IsStringField()
  mimetype?: string;

  @IsStringField()
  description: string;
}

export function IsMediaField(params?: {
  isArray?: boolean;
  required?: boolean;
}) {
  return function (target: any, propertyKey: string): any {
    const { isArray } = getPropMetaData(params, target, propertyKey);

    ApiProperty({ type: MediaDTO, isArray, required: false })(
      target,
      propertyKey,
    );
    // IsObject({ each: isArray })(target, propertyKey);
    Type(() => MediaDTO)(target, propertyKey);
    Expose()(target, propertyKey);
    IsOptional()(target, propertyKey);
  };
}

export function IsUUIDField(params?: {
  version?: '3' | '4' | '5' | 3 | 4 | 5;
  isArray?: boolean;
  required?: boolean;
}) {
  return function (target: any, propertyKey: string): void {
    params ||= {};
    params.required = params.required ?? false;
    params.version = params.version ?? '4';

    const { isArray } = getPropMetaData(params, target, propertyKey);

    ApiProperty({ type: String, required: params.required, isArray })(
      target,
      propertyKey,
    );
    IsUUID(params.version, { each: isArray })(target, propertyKey);
    Expose()(target, propertyKey);

    if (!params?.required) {
      IsOptional()(target, propertyKey);
    }
  };
}
