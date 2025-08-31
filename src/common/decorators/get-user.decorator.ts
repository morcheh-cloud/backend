import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { User } from 'src/app/user/entities/user.entity';

export const GetUser = createParamDecorator<
  keyof User | undefined,
  ExecutionContext
>((data, ctx) => {
  const request = ctx.switchToHttp().getRequest();
  const user = request.user;

  return typeof data === 'undefined' ? user : user[data];
});

export type GetUser<Prop extends keyof User | undefined = undefined> =
  Prop extends undefined ? User : User[Prop];
