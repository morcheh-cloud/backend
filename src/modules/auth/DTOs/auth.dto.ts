import {
	IsNumberField,
	IsStringField,
} from "src/common/decorators/validation.decorator"

export class RegisterPayload {
	@IsStringField({ required: true })
	fullName!: string

	@IsStringField({ required: true })
	email!: string

	@IsStringField({ required: true })
	password!: string
}

export class JWTPayload {
	@IsNumberField({ required: true })
	id!: number

	@IsStringField({ required: true })
	email!: string
}
