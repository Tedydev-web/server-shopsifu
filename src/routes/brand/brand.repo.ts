import { Injectable } from '@nestjs/common'
import {
	CreateBrandBodyType,
	GetBrandsResType,
	UpdateBrandBodyType,
	BrandType,
	BrandIncludeTranslationType
} from 'src/routes/brand/brand.model'
import { ALL_LANGUAGE_CODE } from 'src/shared/constants/other.constant'
import { PaginationQueryType } from 'src/shared/models/request.model'
import { DatabaseService } from 'src/shared/database/services/database.service'

@Injectable()
export class BrandRepo {
	constructor(private databaseService: DatabaseService) {}

	async list(pagination: PaginationQueryType, languageId: string): Promise<GetBrandsResType> {
		const skip = (pagination.page - 1) * pagination.limit
		const take = pagination.limit
		const [totalItems, data] = await Promise.all([
			this.databaseService.brand.count({
				where: {
					deletedAt: null
				}
			}),
			this.databaseService.brand.findMany({
				where: {
					deletedAt: null
				},
				include: {
					brandTranslations: {
						where: languageId === ALL_LANGUAGE_CODE ? { deletedAt: null } : { deletedAt: null, languageId }
					}
				},
				orderBy: {
					createdAt: 'desc'
				},
				skip,
				take
			})
		])
		return {
			data,
			totalItems,
			page: pagination.page,
			limit: pagination.limit,
			totalPages: Math.ceil(totalItems / pagination.limit)
		}
	}

	findById(id: number, languageId: string): Promise<BrandIncludeTranslationType | null> {
		return this.databaseService.brand.findUnique({
			where: {
				id,
				deletedAt: null
			},
			include: {
				brandTranslations: {
					where: languageId === ALL_LANGUAGE_CODE ? { deletedAt: null } : { deletedAt: null, languageId }
				}
			}
		})
	}

	create({
		createdById,
		data
	}: {
		createdById: number | null
		data: CreateBrandBodyType
	}): Promise<BrandIncludeTranslationType> {
		return this.databaseService.brand.create({
			data: {
				...data,
				createdById
			},
			include: {
				brandTranslations: {
					where: { deletedAt: null }
				}
			}
		})
	}

	async update({
		id,
		updatedById,
		data
	}: {
		id: number
		updatedById: number
		data: UpdateBrandBodyType
	}): Promise<BrandIncludeTranslationType> {
		return this.databaseService.brand.update({
			where: {
				id,
				deletedAt: null
			},
			data: {
				...data,
				updatedById
			},
			include: {
				brandTranslations: {
					where: { deletedAt: null }
				}
			}
		})
	}

	delete(
		{
			id,
			deletedById
		}: {
			id: number
			deletedById: number
		},
		isHard?: boolean
	): Promise<BrandType> {
		return isHard
			? this.databaseService.brand.delete({
					where: {
						id
					}
				})
			: this.databaseService.brand.update({
					where: {
						id,
						deletedAt: null
					},
					data: {
						deletedAt: new Date(),
						deletedById
					}
				})
	}
}
