import { Injectable } from '@nestjs/common'
import {
	GetProductTranslationDetailResType,
	CreateProductTranslationBodyType,
	UpdateProductTranslationBodyType
} from 'src/routes/product/product-translation/product-translation.model'
import { ProductTranslationType } from 'src/shared/models/shared-product-translation.model'
import { DatabaseService } from 'src/shared/database/services/database.service'

@Injectable()
export class ProductTranslationRepo {
	constructor(private databaseService: DatabaseService) {}

	findById(id: number): Promise<GetProductTranslationDetailResType | null> {
		return this.databaseService.productTranslation.findUnique({
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
		data: CreateProductTranslationBodyType
	}): Promise<ProductTranslationType> {
		return this.databaseService.productTranslation.create({
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
		data: UpdateProductTranslationBodyType
	}): Promise<ProductTranslationType> {
		return this.databaseService.productTranslation.update({
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
	): Promise<ProductTranslationType> {
		return isHard
			? this.databaseService.productTranslation.delete({
					where: {
						id
					}
				})
			: this.databaseService.productTranslation.update({
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
