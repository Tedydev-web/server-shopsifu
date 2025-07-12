import { Injectable } from '@nestjs/common'
import {
	CreateCategoryBodyType,
	GetAllCategoriesResType,
	UpdateCategoryBodyType,
	CategoryType,
	CategoryIncludeTranslationType
} from 'src/routes/category/category.model'
import { ALL_LANGUAGE_CODE } from 'src/shared/constants/other.constant'
import { DatabaseService } from 'src/shared/database/services/database.service'

@Injectable()
export class CategoryRepo {
	constructor(private databaseService: DatabaseService) {}

	async findAll({
		parentCategoryId,
		languageId
	}: {
		parentCategoryId?: number | null
		languageId: string
	}): Promise<GetAllCategoriesResType> {
		const categories = await this.databaseService.category.findMany({
			where: {
				deletedAt: null,
				parentCategoryId: parentCategoryId ?? null
			},
			include: {
				categoryTranslations: {
					where: languageId === ALL_LANGUAGE_CODE ? { deletedAt: null } : { deletedAt: null, languageId }
				}
			},
			orderBy: {
				createdAt: 'desc'
			}
		})

		return {
			data: categories,
			totalItems: categories.length
		}
	}

	findById({ id, languageId }: { id: number; languageId: string }): Promise<CategoryIncludeTranslationType | null> {
		return this.databaseService.category.findUnique({
			where: {
				id,
				deletedAt: null
			},
			include: {
				categoryTranslations: {
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
		data: CreateCategoryBodyType
	}): Promise<CategoryIncludeTranslationType> {
		return this.databaseService.category.create({
			data: {
				...data,
				createdById
			},
			include: {
				categoryTranslations: {
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
		data: UpdateCategoryBodyType
	}): Promise<CategoryIncludeTranslationType> {
		return this.databaseService.category.update({
			where: {
				id,
				deletedAt: null
			},
			data: {
				...data,
				updatedById
			},
			include: {
				categoryTranslations: {
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
	): Promise<CategoryType> {
		return isHard
			? this.databaseService.category.delete({
					where: {
						id
					}
				})
			: this.databaseService.category.update({
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
