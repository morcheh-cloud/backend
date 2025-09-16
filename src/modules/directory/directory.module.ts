import { Global, Module } from "@nestjs/common"
import { TypeOrmExModule } from "src/common/typeorm-ex.module"
import { DirectoryController } from "src/modules/directory/controller/directory.controller"
import { DirectoryRepository } from "src/modules/directory/repositories/directory.repository"
import { DirectoryService } from "src/modules/directory/services/directory.service"

@Global()
@Module({
	controllers: [DirectoryController],
	exports: [DirectoryService],
	imports: [TypeOrmExModule.forFeature([DirectoryRepository])],
	providers: [DirectoryService],
})
export class DirectoryModule {}
