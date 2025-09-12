import { IsStringField } from "src/common/decorators/validation.decorator"

export class ServerCommandExecLog {
	@IsStringField()
	stdout?: string

	@IsStringField()
	stderr?: string
}

export class ServerLoginLog {}
