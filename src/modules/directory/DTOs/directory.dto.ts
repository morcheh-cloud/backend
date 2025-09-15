import { IsReferenceField } from "src/common/decorators/validation.decorator"
import { Directory } from "src/modules/directory/entities/directory.entity"

export class DirectoryModel extends Directory {
	@IsReferenceField({ type: DirectoryModel })
	children?: Directory[]
}
