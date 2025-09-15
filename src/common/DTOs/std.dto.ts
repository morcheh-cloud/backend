import { IsBooleanField, IsStringField } from "src/common/decorators/validation.decorator"

export class SuccessModel {
	@IsStringField()
	message?: string

	@IsBooleanField()
	success!: boolean

	constructor(message?: string, success: boolean = true) {
		this.message = message
		this.success = success
	}
}
