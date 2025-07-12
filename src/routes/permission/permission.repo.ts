import { Injectable } from '@nestjs/common'
import {
	CreatePermissionBodyType,
	GetPermissionsQueryType,
	GetPermissionsResType,
	PermissionType,
	UpdatePermissionBodyType
} from 'src/routes/permission/permission.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { PaginatedResult, paginate } from 'src/shared/utils/pagination.util'

@Injectable()
export class PermissionRepo {
	constructor(private prismaService: PrismaService) {}

	async list(
		pagination: GetPermissionsQueryType
	): Promise<PaginatedResult<PermissionType>> {
		return paginate<PermissionType>(
			this.prismaService.permission,
			pagination,
			{
				where: {
					deletedAt: null
				}
			},
			['path', 'method', 'description', 'module']
		)
	}

	findById(id: number): Promise<PermissionType | null> {
		return this.prismaService.permission.findUnique({
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
		return this.prismaService.permission.create({
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
		return this.prismaService.permission.update({
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
			? this.prismaService.permission.delete({
					where: {
						id
					}
				})
			: this.prismaService.permission.update({
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
