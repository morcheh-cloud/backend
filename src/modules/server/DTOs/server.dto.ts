import {
	IsEnumField,
	IsNumberField,
	IsReferenceField,
	IsStringField,
} from "src/common/decorators/validation.decorator"
import { DirectoryModel } from "src/modules/directory/DTOs/directory.dto"
import { Directory } from "src/modules/directory/entities/directory.entity"
import { Server, ServerProtocol } from "src/modules/server/entities/server.entity"

export class SaveServerPayload {
	@IsStringField()
	username?: string

	@IsStringField()
	password?: string

	@IsStringField({ required: true })
	directoryId?: string

	@IsStringField()
	name?: string

	@IsStringField()
	description?: string

	@IsStringField()
	address?: string

	@IsNumberField()
	port?: number

	@IsEnumField(ServerProtocol)
	protocol?: ServerProtocol
}

export class ServerModel extends Server {}

export class ServerDirectoryModel extends DirectoryModel {
	@IsReferenceField({ type: ServerModel })
	servers?: Server[]

	@IsReferenceField({ type: ServerDirectoryModel })
	children?: Directory[]
}
