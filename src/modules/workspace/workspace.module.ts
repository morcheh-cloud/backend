import { Module } from "@nestjs/common";
import { TypeOrmExModule } from "src/common/typeorm-ex.module";
import { WorkspaceController } from "src/modules/workspace/controllers/workspace.controller";
import { WorkspaceRepository } from "src/modules/workspace/repositories/workspace.repository";
import { WorkspaceService } from "src/modules/workspace/services/workspace.service";

@Module({
  controllers: [WorkspaceController],
  exports: [WorkspaceService],
  imports: [TypeOrmExModule.forFeature([WorkspaceRepository])],
  providers: [WorkspaceService],
})
export class WorkspaceModule {}
