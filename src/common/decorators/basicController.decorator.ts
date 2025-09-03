import {
  applyDecorators,
  ClassSerializerInterceptor,
  Controller,
  UseGuards,
  UseInterceptors,
} from "@nestjs/common";
import { ApiBearerAuth, ApiTags } from "@nestjs/swagger";
import { AuthGuard } from "src/common/guards/auth.guard";

export const BasicController = (route: string, apiTagName?: string) => {
  return applyDecorators(
    ApiBearerAuth(),
    UseInterceptors(ClassSerializerInterceptor),
    ApiTags(apiTagName?.toUpperCase() || route?.toUpperCase()),
    UseGuards(AuthGuard),
    Controller(route)
  );
};
