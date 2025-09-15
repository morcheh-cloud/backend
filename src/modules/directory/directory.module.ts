import { Module } from "@nestjs/common"
import { TypeOrmExModule } from "src/common/typeorm-ex.module"
import { DirectoryRepository } from "src/modules/directory/repositories/directory.repository"

@Module({
	imports: [TypeOrmExModule.forFeature([DirectoryRepository])],
})
export class DirectoryModule {}
