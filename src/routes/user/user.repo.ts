import { Injectable } from '@nestjs/common'
import { CreateUserBodyType, GetUsersQueryType, GetUsersResType, UpdateUserBodyType } from 'src/routes/user/user.model'
import { DatabaseService } from 'src/shared/database/services/database.service'
import { UserType } from 'src/shared/models/shared-user.model'

@Injectable()
export class UserRepo {
	constructor(private databaseService: DatabaseService) {}

	async list(pagination: GetUsersQueryType): Promise<GetUsersResType> {
		const skip = (pagination.page - 1) * pagination.limit
		const take = pagination.limit
		const [totalItems, data] = await Promise.all([
			this.databaseService.user.count({
				where: {
					deletedAt: null
				}
			}),
			this.databaseService.user.findMany({
				where: {
					deletedAt: null
				},
				skip,
				take,
				include: {
					role: true
				}
			})
		])
		return {
			data,
			totalItems,
			page: pagination.page,
			limit: pagination.limit,
			totalPages: Math.ceil(totalItems / pagination.limit)
		}
	}

	create({ createdById, data }: { createdById: number | null; data: CreateUserBodyType }): Promise<UserType> {
		return this.databaseService.user.create({
			data: {
				...data,
				createdById
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
	): Promise<UserType> {
		return isHard
			? this.databaseService.user.delete({
					where: {
						id
					}
				})
			: this.databaseService.user.update({
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
