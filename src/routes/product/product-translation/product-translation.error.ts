import { UnprocessableEntityException } from '@nestjs/common'

export const ProductTranslationAlreadyExistsException =
	new UnprocessableEntityException([
		{
			path: 'productId',
			message: 'product.productTranslation.error.ALREADY_EXISTS'
		}
	])
