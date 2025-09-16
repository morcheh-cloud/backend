import { IsEnumField, IsReferenceField, IsStringField } from "src/common/decorators/validation.decorator"
import { Directory, DirectoryType } from "src/modules/directory/entities/directory.entity"

export class DirectoryModel extends Directory {
	@IsReferenceField({ type: DirectoryModel })
	children?: Directory[]
}

export class SaveDirectoryPayload {
	@IsStringField({ required: true })
	name!: string

	@IsEnumField(DirectoryType, { required: true })
	type!: DirectoryType

	@IsStringField({ required: true })
	parentId?: string
}
