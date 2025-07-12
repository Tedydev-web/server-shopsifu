import { Injectable } from '@nestjs/common'
import {
	CreateRoleBodyType,
	GetRolesQueryType,
	GetRolesResType,
	RoleWithPermissionsType,
	UpdateRoleBodyType
} from 'src/routes/role/role.model'
import { RoleType } from 'src/shared/models/shared-role.model'
import { DatabaseService } from 'src/shared/database/services/database.service'

@Injectable()
export class RoleRepo {
	constructor(private databaseService: DatabaseService) {}

	async list(pagination: GetRolesQueryType): Promise<GetRolesResType> {
		const skip = (pagination.page - 1) * pagination.limit
		const take = pagination.limit
		const [totalItems, data] = await Promise.all([
			this.databaseService.role.count({
				where: {
					deletedAt: null
				}
			}),
			this.databaseService.role.findMany({
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

	findById(id: number): Promise<RoleWithPermissionsType | null> {
		return this.databaseService.role.findUnique({
			where: {
				id,
				deletedAt: null
			},
			include: {
				permissions: {
					where: {
						deletedAt: null
					}
				}
			}
		})
	}

	create({ createdById, data }: { createdById: number | null; data: CreateRoleBodyType }): Promise<RoleType> {
		return this.databaseService.role.create({
			data: {
				...data,
				createdById
			}
		})
	}

	async update({
		id,
		updatedById,
		data
	}: {
		id: number
		updatedById: number
		data: UpdateRoleBodyType
	}): Promise<RoleType> {
		// Kiểm tra nếu có bất cứ permissionId nào mà đã soft delete thì không cho phép cập nhật
		if (data.permissionIds.length > 0) {
			const permissions = await this.databaseService.permission.findMany({
				where: {
					id: {
						in: data.permissionIds
					}
				}
			})
			const deletedPermission = permissions.filter(permission => permission.deletedAt)
			if (deletedPermission.length > 0) {
				const deletedIds = deletedPermission.map(permission => permission.id).join(', ')
				throw new Error(`Permission with id has been deleted: ${deletedIds}`)
			}
		}

		return this.databaseService.role.update({
			where: {
				id,
				deletedAt: null
			},
			data: {
				name: data.name,
				description: data.description,
				isActive: data.isActive,
				permissions: {
					set: data.permissionIds.map(id => ({ id }))
				},
				updatedById
			},
			include: {
				permissions: {
					where: {
						deletedAt: null
					}
				}
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
	): Promise<RoleType> {
		return isHard
			? this.databaseService.role.delete({
					where: {
						id
					}
				})
			: this.databaseService.role.update({
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
