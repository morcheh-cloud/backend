import { IsEnumField, IsNumberField, IsStringField } from "src/common/decorators/validation.decorator"
import { Server, ServerProtocol } from "src/modules/server/entities/server.entity"

export class SaveServerPayload {
	@IsStringField()
	username?: string

	@IsStringField()
	password?: string

	@IsNumberField()
	directoryId?: number

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
