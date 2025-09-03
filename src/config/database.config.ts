import type { TypeOrmModuleOptions } from "@nestjs/typeorm/dist/interfaces/typeorm-options.interface"
import { DataSource, type DataSourceOptions } from "typeorm"

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
}

export let TypeormDataSource: DataSource
export async function InitDataSource(options?: DataSourceOptions) {
	const dataSource = await new DataSource(options as any).initialize()
	TypeormDataSource = dataSource
	return dataSource
}
