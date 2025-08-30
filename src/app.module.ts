import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm/dist/typeorm.module";
import { databaseConfig } from "src/config/database.config";
import { AuthModule } from "./app/auth/auth.module";
import { UserModule } from "./app/user/user.module";

@Module({
	controllers: [],
	imports: [TypeOrmModule.forRoot(databaseConfig), AuthModule, UserModule],
	providers: [],
})
export class AppModule {}
