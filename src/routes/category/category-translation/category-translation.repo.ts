import { Injectable } from '@nestjs/common'
import {
	GetCategoryTranslationDetailResType,
	CreateCategoryTranslationBodyType,
	CategoryTranslationType,
	UpdateCategoryTranslationBodyType
} from 'src/routes/category/category-translation/category-translation.model'
import { DatabaseService } from 'src/shared/database/services/database.service'

@Injectable()
export class CategoryTranslationRepo {
	constructor(private databaseService: DatabaseService) {}

	findById(id: number): Promise<GetCategoryTranslationDetailResType | null> {
		return this.databaseService.categoryTranslation.findUnique({
			where: {
				id,
				deletedAt: null
			}
		})
	}

	create({
		createdById,
		data
	}: {
		createdById: number | null
		data: CreateCategoryTranslationBodyType
	}): Promise<CategoryTranslationType> {
		return this.databaseService.categoryTranslation.create({
			data: {
				...data,
				createdById
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
		data: UpdateCategoryTranslationBodyType
	}): Promise<CategoryTranslationType> {
		return this.databaseService.categoryTranslation.update({
			where: {
				id,
				deletedAt: null
			},
			data: {
				...data,
				updatedById
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
	): Promise<CategoryTranslationType> {
		return isHard
			? this.databaseService.categoryTranslation.delete({
					where: {
						id
					}
				})
			: this.databaseService.categoryTranslation.update({
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
