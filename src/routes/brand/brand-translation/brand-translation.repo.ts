import { Injectable } from '@nestjs/common'
import {
	GetBrandTranslationDetailResType,
	CreateBrandTranslationBodyType,
	BrandTranslationType,
	UpdateBrandTranslationBodyType
} from 'src/routes/brand/brand-translation/brand-translation.model'
import { DatabaseService } from 'src/shared/database/services/database.service'

@Injectable()
export class BrandTranslationRepo {
	constructor(private databaseService: DatabaseService) {}

	findById(id: number): Promise<GetBrandTranslationDetailResType | null> {
		return this.databaseService.brandTranslation.findUnique({
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
		data: CreateBrandTranslationBodyType
	}): Promise<BrandTranslationType> {
		return this.databaseService.brandTranslation.create({
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
		data: UpdateBrandTranslationBodyType
	}): Promise<BrandTranslationType> {
		return this.databaseService.brandTranslation.update({
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
	): Promise<BrandTranslationType> {
		return isHard
			? this.databaseService.brandTranslation.delete({
					where: {
						id
					}
				})
			: this.databaseService.brandTranslation.update({
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
