import { ForbiddenException, Injectable } from '@nestjs/common'
import { ProductRepo } from 'src/routes/product/product.repo'
import {
	CreateProductBodyType,
	GetManageProductsQueryType,
	GetProductsQueryType,
	UpdateProductBodyType
} from 'src/routes/product/product.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError } from 'src/shared/helpers'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { RoleName } from 'src/shared/constants/role.constant'

@Injectable()
export class ManageProductService {
	constructor(
		private productRepo: ProductRepo,
		private i18n: I18nService<I18nTranslations>
	) {}

	/**
	 * Kiểm tra nếu người dùng không phải là người tạo sản phẩm hoặc admin thì không cho tiếp tục
	 */
	validatePrivilege({
		userIdRequest,
		roleNameRequest,
		createdById
	}: {
		userIdRequest: number
		roleNameRequest: string
		createdById: number | undefined | null
	}) {
		if (
			userIdRequest !== createdById &&
			roleNameRequest !== RoleName.Admin
		) {
			throw new ForbiddenException()
		}
		return true
	}

	/**
	 * @description: Xem danh sách sản phẩm của một shop, bắt buộc phải truyền query param là `createdById`
	 */
	async list(props: {
		query: GetManageProductsQueryType
		userIdRequest: number
		roleNameRequest: string
	}) {
		this.validatePrivilege({
			userIdRequest: props.userIdRequest,
			roleNameRequest: props.roleNameRequest,
			createdById: props.query.createdById
		})
		const data = await this.productRepo.list({
			...props.query,
			languageId: I18nContext.current()?.lang as string,
			createdById: props.query.createdById,
			isPublic: props.query.isPublic
		})
		return {
			...data,
			message: this.i18n.t('product.product.success.GET_PRODUCTS')
		}
	}

	async getDetail(props: {
		productId: number
		userIdRequest: number
		roleNameRequest: string
	}) {
		const product = await this.productRepo.getDetail({
			productId: props.productId,
			languageId: I18nContext.current()?.lang as string
		})

		if (!product) {
			throw NotFoundRecordException
		}
		this.validatePrivilege({
			userIdRequest: props.userIdRequest,
			roleNameRequest: props.roleNameRequest,
			createdById: product.createdById
		})
		return {
			data: product,
			message: this.i18n.t('product.product.success.GET_PRODUCT_DETAIL')
		}
	}

	async create({
		data,
		createdById
	}: {
		data: CreateProductBodyType
		createdById: number
	}) {
		const product = await this.productRepo.create({
			createdById,
			data
		})
		return {
			data: product,
			message: this.i18n.t('product.product.success.CREATE_SUCCESS')
		}
	}

	async update({
		productId,
		data,
		updatedById,
		roleNameRequest
	}: {
		productId: number
		data: UpdateProductBodyType
		updatedById: number
		roleNameRequest: string
	}) {
		const product = await this.productRepo.findById(productId)
		if (!product) {
			throw NotFoundRecordException
		}
		this.validatePrivilege({
			userIdRequest: updatedById,
			roleNameRequest,
			createdById: product.createdById
		})
		try {
			const updatedProduct = await this.productRepo.update({
				id: productId,
				updatedById,
				data
			})
			return {
				data: updatedProduct,
				message: this.i18n.t('product.product.success.UPDATE_SUCCESS')
			}
		} catch (error) {
			if (isNotFoundPrismaError(error)) {
				throw NotFoundRecordException
			}
			throw error
		}
	}

	async delete({
		productId,
		deletedById,
		roleNameRequest
	}: {
		productId: number
		deletedById: number
		roleNameRequest: string
	}) {
		const product = await this.productRepo.findById(productId)
		if (!product) {
			throw NotFoundRecordException
		}
		this.validatePrivilege({
			userIdRequest: deletedById,
			roleNameRequest,
			createdById: product.createdById
		})
		try {
			await this.productRepo.delete({
				id: productId,
				deletedById
			})
			return {
				message: this.i18n.t('product.product.success.DELETE_SUCCESS')
			}
		} catch (error) {
			if (isNotFoundPrismaError(error)) {
				throw NotFoundRecordException
			}
			throw error
		}
	}
}
