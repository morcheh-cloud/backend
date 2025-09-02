import {
  applyDecorators,
  ClassSerializerInterceptor,
  Controller,
  UseInterceptors,
} from "@nestjs/common";
import { ApiBearerAuth, ApiTags } from "@nestjs/swagger";

export const BasicController = (route: string, apiTagName?: string) => {
  return applyDecorators(
    ApiBearerAuth(),
    UseInterceptors(ClassSerializerInterceptor),
    ApiTags(apiTagName?.toUpperCase() || route?.toUpperCase()),
    Controller(route)
  );
};
