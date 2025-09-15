import { Global, Module } from "@nestjs/common"
import { TypeOrmExModule } from "src/common/typeorm-ex.module"
import { DirectoryRepository } from "src/modules/directory/repositories/directory.repository"
import { DirectoryService } from "src/modules/directory/services/directory.service"

@Global()
@Module({
	exports: [DirectoryService],
	imports: [TypeOrmExModule.forFeature([DirectoryRepository])],
	providers: [DirectoryService],
})
export class DirectoryModule {}
