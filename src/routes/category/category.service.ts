import { Injectable } from '@nestjs/common'
import { CategoryRepo } from 'src/routes/category/category.repo'
import {
	CreateCategoryBodyType,
	UpdateCategoryBodyType
} from 'src/routes/category/category.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError } from 'src/shared/helpers'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'

@Injectable()
export class CategoryService {
	constructor(
		private categoryRepo: CategoryRepo,
		private i18n: I18nService<I18nTranslations>
	) {}

	async findAll(parentCategoryId?: number | null) {
		const result = await this.categoryRepo.findAll({
			parentCategoryId,
			languageId: I18nContext.current()?.lang as string
		})
		return {
			...result,
			message: this.i18n.t('category.category.success.GET_SUCCESS')
		}
	}

	async findById(id: number) {
		const category = await this.categoryRepo.findById({
			id,
			languageId: I18nContext.current()?.lang as string
		})
		if (!category) {
			throw NotFoundRecordException
		}
		return {
			message: this.i18n.t(
				'category.category.success.GET_DETAIL_SUCCESS'
			),
			data: category
		}
	}

	async create({
		data,
		createdById
	}: {
		data: CreateCategoryBodyType
		createdById: number
	}) {
		const category = await this.categoryRepo.create({
			createdById,
			data
		})
		return {
			data: category,
			message: this.i18n.t('category.category.success.CREATE_SUCCESS')
		}
	}

	async update({
		id,
		data,
		updatedById
	}: {
		id: number
		data: UpdateCategoryBodyType
		updatedById: number
	}) {
		try {
			const category = await this.categoryRepo.update({
				id,
				updatedById,
				data
			})
			return {
				data: category,
				message: this.i18n.t('category.category.success.UPDATE_SUCCESS')
			}
		} catch (error) {
			if (isNotFoundPrismaError(error)) {
				throw NotFoundRecordException
			}
			throw error
		}
	}

	async delete({ id, deletedById }: { id: number; deletedById: number }) {
		try {
			await this.categoryRepo.delete({
				id,
				deletedById
			})
			return {
				message: this.i18n.t('category.category.success.DELETE_SUCCESS')
			}
		} catch (error) {
			if (isNotFoundPrismaError(error)) {
				throw NotFoundRecordException
			}
			throw error
		}
	}
}
