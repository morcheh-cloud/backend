import { Global, Module } from "@nestjs/common"
import { AuthModule } from "src/modules/auth/auth.module"
import { WorkspaceModule } from "src/modules/workspace/workspace.module"

@Global()
@Module({
	imports: [WorkspaceModule, AuthModule],
})
export class CommonModule {}
