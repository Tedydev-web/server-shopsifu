/* eslint-disable @typescript-eslint/no-namespace */
import { ProductTranslationType } from 'src/shared/models/shared-product-translation.model'
import { VariantsType } from 'src/shared/models/shared-product.model'

declare global {
	export type PrismaJsonVariants = VariantsType
	export type PrismaJsonProductTranslations = Pick<
		ProductTranslationType,
		'id' | 'name' | 'description' | 'languageId'
	>[]
	export type PrismaJsonReceiver = {
		name: string
		phone: string
		address: string
	}
}
