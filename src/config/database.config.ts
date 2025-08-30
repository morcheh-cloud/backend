import type { TypeOrmModuleOptions } from "@nestjs/typeorm/dist/interfaces/typeorm-options.interface";

export const databaseConfig: TypeOrmModuleOptions = {
	autoLoadEntities: true,
	database: "postgres",
	entities: [`${__dirname}/../**/*.entity.{js,ts}`],
	host: "localhost",
	password: "postgres",
	port: 5432,
	synchronize: true,
	type: "postgres",
	username: "postgres",
};
