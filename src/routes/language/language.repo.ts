import { Injectable } from '@nestjs/common'
import { CreateLanguageBodyType, LanguageType, UpdateLanguageBodyType } from 'src/routes/language/language.model'
import { DatabaseService } from 'src/shared/database/services/database.service'

@Injectable()
export class LanguageRepo {
	constructor(private databaseService: DatabaseService) {}

	findAll(): Promise<LanguageType[]> {
		return this.databaseService.language.findMany({
			where: {
				deletedAt: null
			}
		})
	}

	findById(id: string): Promise<LanguageType | null> {
		return this.databaseService.language.findUnique({
			where: {
				id,
				deletedAt: null
			}
		})
	}

	create({ createdById, data }: { createdById: number; data: CreateLanguageBodyType }): Promise<LanguageType> {
		return this.databaseService.language.create({
			data: {
				...data,
				createdById
			}
		})
	}

	update({
		id,
		updatedById,
		data
	}: {
		id: string
		updatedById: number
		data: UpdateLanguageBodyType
	}): Promise<LanguageType> {
		return this.databaseService.language.update({
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

	delete(id: string, isHard?: boolean): Promise<LanguageType> {
		return isHard
			? this.databaseService.language.delete({
					where: {
						id
					}
				})
			: this.databaseService.language.update({
					where: {
						id,
						deletedAt: null
					},
					data: {
						deletedAt: new Date()
					}
				})
	}
}
