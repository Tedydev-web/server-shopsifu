import { Injectable } from '@nestjs/common'
import { NotFoundRecordException } from 'src/shared/error'
import {
	isNotFoundPrismaError,
	isUniqueConstraintPrismaError
} from 'src/shared/helpers'
import { ProductTranslationRepo } from 'src/routes/product/product-translation/product-translation.repo'
import { ProductTranslationAlreadyExistsException } from 'src/routes/product/product-translation/product-translation.error'
import {
	CreateProductTranslationBodyType,
	UpdateProductTranslationBodyType
} from 'src/routes/product/product-translation/product-translation.model'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'

@Injectable()
export class ProductTranslationService {
	constructor(
		private productTranslationRepo: ProductTranslationRepo,
		private i18n: I18nService<I18nTranslations>
	) {}

	async findById(id: number) {
		const product = await this.productTranslationRepo.findById(id)
		if (!product) {
			throw NotFoundRecordException
		}
		return {
			data: product,
			message: this.i18n.t(
				'product.productTranslation.success.GET_DETAIL_SUCCESS'
			)
		}
	}

	async create({
		data,
		createdById
	}: {
		data: CreateProductTranslationBodyType
		createdById: number
	}) {
		try {
			const productTranslation = await this.productTranslationRepo.create(
				{
					createdById,
					data
				}
			)
			return {
				data: productTranslation,
				message: this.i18n.t(
					'product.productTranslation.success.CREATE_SUCCESS'
				)
			}
		} catch (error) {
			if (isUniqueConstraintPrismaError(error)) {
				throw ProductTranslationAlreadyExistsException
			}
			throw error
		}
	}

	async update({
		id,
		data,
		updatedById
	}: {
		id: number
		data: UpdateProductTranslationBodyType
		updatedById: number
	}) {
		try {
			const product = await this.productTranslationRepo.update({
				id,
				updatedById,
				data
			})
			return {
				data: product,
				message: this.i18n.t(
					'product.productTranslation.success.UPDATE_SUCCESS'
				)
			}
		} catch (error) {
			if (isUniqueConstraintPrismaError(error)) {
				throw ProductTranslationAlreadyExistsException
			}
			if (isNotFoundPrismaError(error)) {
				throw NotFoundRecordException
			}
			throw error
		}
	}

	async delete({ id, deletedById }: { id: number; deletedById: number }) {
		try {
			await this.productTranslationRepo.delete({
				id,
				deletedById
			})
			return {
				message: this.i18n.t(
					'product.productTranslation.success.DELETE_SUCCESS'
				)
			}
		} catch (error) {
			if (isNotFoundPrismaError(error)) {
				throw NotFoundRecordException
			}
			throw error
		}
	}
}
