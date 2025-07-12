import { UnprocessableEntityException } from '@nestjs/common'

export const CategoryTranslationAlreadyExistsException =
	new UnprocessableEntityException([
		{
			path: 'languageId',
			message: 'category.categoryTranslation.error.ALREADY_EXISTS'
		}
	])
