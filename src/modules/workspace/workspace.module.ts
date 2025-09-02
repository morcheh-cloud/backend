import { Module } from "@nestjs/common";
import { WorkspaceRepository } from "src/modules/workspace/repositories/workspace.repository";

@Module({
  imports: [WorkspaceRepository],
})
export class WorkspaceModule {}
