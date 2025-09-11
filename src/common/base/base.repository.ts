import { BadRequestException, InternalServerErrorException, Logger, NotFoundException } from "@nestjs/common"
import { isEmpty, isNumber, isUndefined, omitBy } from "lodash"
import { IPagination, Paginate } from "src/lib/pagination"
import { User } from "src/modules/user/entities/user.entity"
import {
	DeepPartial,
	FindManyOptions,
	FindOneOptions,
	FindOptionsOrder,
	FindOptionsRelations,
	QueryRunner,
	Repository,
	SaveOptions,
	SelectQueryBuilder,
} from "typeorm"
import { ObjectLiteral } from "typeorm/common/ObjectLiteral"
import { QueryDeepPartialEntity } from "typeorm/query-builder/QueryPartialEntity.js"

export interface PaginationInterface {
	page?: number
	limit?: number
}

interface SQB<Entity extends ObjectLiteral> extends SelectQueryBuilder<Entity> {
	pagination(this: SQB<Entity>, params: { page: number; limit?: number; mode?: "legacy" | "modern" }): SQB<Entity>
}

export interface CustomFindManyOptions<Entity> extends FindManyOptions<Entity> {
	page?: number
	limit?: number
	loadMedia?: boolean
}

export type CustomFindOneOptions<Entity> = FindOneOptions<Entity>

export interface CustomSaveOptions<Entity> extends SaveOptions {
	user?: User
	relations?: FindOptionsRelations<Entity>
}

export class BaseRepository<Entity extends ObjectLiteral> extends Repository<Entity> {
	//
	private readonly logger = new Logger()
	// private readonly mediaLoaderService = new MediaLoaderService();

	async isExistOrFail(optionsOrConditions: CustomFindOneOptions<Entity>) {
		const count = await this.count({
			...optionsOrConditions,
			select: ["id"], // Updated to use an array of strings
		})

		if (count === 0) {
			throw new NotFoundException("is not exist")
		}
	}

	// override findOne(options: FindOneOptions<Entity>): Promise<Entity | null> {

	// }

	override async findOne(optionsOrConditions: CustomFindOneOptions<Entity>): Promise<Entity | null> {
		const result = await super.findOne(optionsOrConditions)

		// await this.mediaLoaderService.loadMedia(result);

		return result
	}

	override async find(optionsOrConditions?: CustomFindManyOptions<Entity>): Promise<Entity[]> {
		let pagination: IPagination = {}
		if (typeof optionsOrConditions?.page === "number" && typeof optionsOrConditions.limit === "number") {
			pagination = Paginate(optionsOrConditions.page, optionsOrConditions.limit)
		}

		const order: FindOptionsOrder<any> = optionsOrConditions?.order || {
			id: "desc",
		}

		const result = await super.find({
			...optionsOrConditions,
			...pagination,
			order,
		})

		// if (optionsOrConditions?.loadMedia !== false) {
		//   await this.mediaLoaderService.loadMedia(result);
		// }

		return result
	}

	override async findAndCount(optionsOrConditions?: CustomFindManyOptions<Entity>): Promise<[Entity[], number]> {
		//
		const order: FindOptionsOrder<any> = optionsOrConditions?.order || {
			id: "desc",
		}

		let pagination: IPagination = {}
		if (typeof optionsOrConditions?.page === "number" && typeof optionsOrConditions.limit === "number") {
			pagination = Paginate(optionsOrConditions.page, optionsOrConditions.limit)
		}

		const [result, total] = await super.findAndCount({
			...optionsOrConditions,
			...pagination,
			order,
		})

		// if (optionsOrConditions?.loadMedia !== false) {
		//   await this.mediaLoaderService.loadMedia(result);
		// }

		return [result, total]
	}

	override async findOneOrFail(optionsOrConditions: CustomFindOneOptions<Entity>): Promise<Entity> {
		const result = await this.findOne(optionsOrConditions)

		if (!result) {
			throw new NotFoundException()
		}

		// await this.mediaLoaderService.loadMedia(result);

		return result
	}

	async createAndSave(data: DeepPartial<Entity>, options?: CustomSaveOptions<Entity>): Promise<Entity> {
		if (isEmpty(data)) {
			throw new InternalServerErrorException()
		}

		let savedEntity: Entity
		const clearedData: Record<string, any> = omitBy(data as any, (key: string) => isUndefined(key))
		delete clearedData["id"]

		const entityData: any = super.create(clearedData as any)

		if (options?.user) {
			// entityData.createdBy = options?.user?.id || null;
			entityData.createdBy = options?.user || null
			// delete options.user;
		}

		try {
			savedEntity = await super.save(entityData, options)
			// await this.mediaLoaderService.updateMedia(
			//   savedEntity.id,
			//   clearedData,
			//   this.target,
			//   this.metadata.tableName
			// );
		} catch (e) {
			this.logger.error(e, `QUERY ${this.metadata.tableName}`)
			throw new InternalServerErrorException()
		}

		const result = await this.findOneOrFail({
			relations: options?.relations || {},
			where: { id: savedEntity["id"] }, // Explicitly cast id to match the expected type
		})

		return result
	}

	async updateById(
		id: number,
		data: QueryDeepPartialEntity<Entity>,
		options?: CustomSaveOptions<Entity>,
	): Promise<Entity> {
		//
		if (isEmpty(data)) {
			throw new InternalServerErrorException("Invalid data to update")
		}

		const clearedData = omitBy(data, key => isUndefined(key))
		delete clearedData["id"]
		id = +id

		const entityData: any = super.create(clearedData as any)

		if (options?.user) {
			// entityData.updatedBy = options?.user?.id || null;
			entityData.updatedBy = options?.user || null
			// delete options.user;
		}

		if (!isNumber(id) || Number.isNaN(id)) {
			throw new BadRequestException("Invalid id")
		}

		try {
			// update db
			await super.save({ ...entityData, id })

			// update media
			// await this.mediaLoaderService.updateMedia(
			//   id,
			//   clearedData,
			//   this.target,
			//   this.metadata.tableName
			// );
		} catch (e) {
			this.logger.error(e, `QUERY ${this.metadata.tableName}`)
			throw new InternalServerErrorException("Failed to update")
		}

		const record = await this.findOneOrFail({
			relations: options?.relations || {},
			where: { id: id as any },
		})

		return record
	}

	// async softDelete(
	//   criteria:
	//     | string
	//     | number
	//     | Date
	//     | string[]
	//     | number[]
	//     | Date[]
	//     | FindOptionsWhere<Entity>,
	//   options: { user?: User } = {}
	// ): Promise<UpdateResult> {
	//   //

	//   if (options?.user && isNumber(+criteria)) {
	//     await super.save({ deletedById: options.user.id, id: +criteria } as any);
	//   }

	//   return await super.softDelete(criteria);
	// }

	// async restore(
	//   criteria:
	//     | string
	//     | number
	//     | Date
	//     | ObjectId
	//     | string[]
	//     | number[]
	//     | Date[]
	//     | ObjectId[]
	//     | FindOptionsWhere<Entity>,
	//   options: { user?: User } = {}
	// ): Promise<UpdateResult> {
	//   const result = await super.restore(criteria);

	//   if (options?.user && isNumber(+criteria)) {
	//     await super.save({ id: +criteria, restoredBy: options.user.id } as any);
	//   }
	//   return result;
	// }

	private customCreateQueryBuilder(alias?: string, queryRunner?: QueryRunner): SelectQueryBuilder<Entity> {
		return super.createQueryBuilder(alias, queryRunner)
	}

	private queryBuilderCustomFunctions(qb: SQB<Entity>): void {
		/**
		 * pagination function
		 */
		qb.pagination = function (
			this: SQB<Entity>,
			params: { page: number; limit?: number; mode?: "legacy" | "modern" },
		): SQB<Entity> {
			const mode = params?.mode || "modern"
			const limit = params?.limit || 10

			const { page } = params

			params.mode ||= "modern"

			if (mode === "modern") {
				this.take(limit).skip(page * limit)
			} else if (mode === "legacy") {
				this.limit(limit).offset(page * limit)
			}

			return this
		}
	}

	override createQueryBuilder(alias?: string, queryRunner?: QueryRunner): SQB<Entity> {
		const qb = this.customCreateQueryBuilder(alias, queryRunner)
		this.queryBuilderCustomFunctions(qb as SQB<Entity>)
		return qb as SQB<Entity>
	}
}
