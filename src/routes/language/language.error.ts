import { UnprocessableEntityException } from '@nestjs/common'

export const LanguageAlreadyExistsException = new UnprocessableEntityException([
	{
		message: 'language.language.error.ALREADY_EXISTS',
		path: 'id'
	}
])
