import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { Workspace } from "src/modules/workspace/entities/workspace.entity";

export const GetWorkspace = createParamDecorator<
  keyof Workspace | undefined,
  ExecutionContext
>((data, ctx) => {
  const request = ctx.switchToHttp().getRequest();
  const workspace = request["workspace"];
  return typeof data === "undefined" ? workspace : workspace[data];
});

export type GetWorkspace<k extends keyof Workspace | undefined = undefined> =
  k extends undefined
    ? Workspace
    : k extends keyof Workspace
    ? Workspace[k]
    : never;
