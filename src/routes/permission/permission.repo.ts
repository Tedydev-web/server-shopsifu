import { Injectable } from '@nestjs/common'
import {
	CreatePermissionBodyType,
	GetPermissionsQueryType,
	GetPermissionsResType,
	PermissionType,
	UpdatePermissionBodyType
} from 'src/routes/permission/permission.model'
import { DatabaseService } from 'src/shared/database/services/database.service'

@Injectable()
export class PermissionRepo {
	constructor(private databaseService: DatabaseService) {}

	async list(pagination: GetPermissionsQueryType): Promise<GetPermissionsResType> {
		const skip = (pagination.page - 1) * pagination.limit
		const take = pagination.limit
		const [totalItems, data] = await Promise.all([
			this.databaseService.permission.count({
				where: {
					deletedAt: null
				}
			}),
			this.databaseService.permission.findMany({
				where: {
					deletedAt: null
				},
				skip,
				take
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

	findById(id: number): Promise<PermissionType | null> {
		return this.databaseService.permission.findUnique({
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
		data: CreatePermissionBodyType
	}): Promise<PermissionType> {
		return this.databaseService.permission.create({
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
		id: number
		updatedById: number
		data: UpdatePermissionBodyType
	}): Promise<PermissionType> {
		return this.databaseService.permission.update({
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
	): Promise<PermissionType> {
		return isHard
			? this.databaseService.permission.delete({
					where: {
						id
					}
				})
			: this.databaseService.permission.update({
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
