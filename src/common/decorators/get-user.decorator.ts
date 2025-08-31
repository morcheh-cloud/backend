import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { User } from "src/modules/user/entities/user.entity";

export const GetUser = createParamDecorator<
  keyof User | undefined,
  ExecutionContext
>((data, ctx) => {
  const request = ctx.switchToHttp().getRequest();
  const user = request.user;

  return typeof data === "undefined" ? user : user[data];
});

export type GetUser<k extends keyof User | undefined = undefined> =
  k extends undefined ? User : k extends keyof User ? User[k] : never;
