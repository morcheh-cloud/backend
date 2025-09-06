import { IsNumberField, IsReferenceField, IsStringField } from "src/common/decorators/validation.decorator"

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
	id!: string

	@IsStringField({ required: true })
	email!: string
}

export class RegisterModel {
	@IsReferenceField({ required: true })
	data!: JWTPayload

	@IsStringField({ required: true })
	access_token!: string
}

export class LoginPayload {
	@IsStringField({ required: true })
	email!: string

	@IsStringField({ required: true })
	password!: string
}

export class LoginModel {
	@IsReferenceField({ required: true })
	data!: JWTPayload

	@IsStringField({ required: true })
	access_token!: string
}
