import { ArgumentMetadata, Injectable, PipeTransform } from "@nestjs/common"
import { isArray, isEmpty } from "lodash"
import {
	RelationalFieldMetaDataKey,
	relationalFieldMetaData,
} from "src/common/decorators/validation.decorator"

@Injectable()
export class CreateEntityModelPipe implements PipeTransform {
	private transferData(
		ids: number[] | number,
	): { id: number } | { id: number }[] {
		if (isArray(ids)) {
			return ids.flatMap((i) => [{ id: +i }])
		} else {
			return { id: +ids }
		}
	}

	// biome-ignore lint/suspicious/noExplicitAny: <explanation>
	async transform(value: any, metaData: ArgumentMetadata): Promise<unknown> {
		const payload = isArray(value) ? [...value] : [{ ...value }]

		const PK_Fields: relationalFieldMetaData[] = metaData.metatype
			? Reflect.getMetadata(RelationalFieldMetaDataKey, metaData.metatype)
			: undefined

		if (!PK_Fields) return value

		for (const field of PK_Fields) {
			/**
			 *
			 */
			for (const item of payload) {
				/**
				 *
				 */

				if (isEmpty(item[field?.property]) && !item[field?.property]) continue

				const numbers = item[field?.property]

				if (field?.isArray && !isArray(item[field?.property])) {
					item[field?.property] = [item[field?.property]]
				}

				const isMany = isArray(numbers)
				const ids = isMany ? [...numbers] : [{ ...numbers }]

				item[field?.property] = this.transferData(isMany ? ids : numbers)
			}
		}

		return isArray(value) ? value : payload[0]
	}
}
