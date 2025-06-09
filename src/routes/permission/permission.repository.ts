import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Permission } from './permission.model' // Import từ model mới tạo
import { CreatePermissionDto, UpdatePermissionDto } from './permission.dto'

@Injectable()
export class PermissionRepository {
  constructor(private readonly prisma: PrismaService) {}

  async create(createPermissionDto: CreatePermissionDto): Promise<Permission> {
    const { action, subject, description, category } = createPermissionDto
    return this.prisma.permission.create({
      data: {
        action,
        subject,
        description,
        category
      }
    })
  }

  async findAll(): Promise<Permission[]> {
    return this.prisma.permission.findMany()
  }

  async findById(id: number): Promise<Permission | null> {
    return this.prisma.permission.findUnique({
      where: { id }
    })
  }

  async findByActionAndSubject(action: string, subject: string): Promise<Permission | null> {
    return this.prisma.permission.findUnique({
      where: { UQ_action_subject: { action, subject } }
    })
  }

  async update(id: number, updatePermissionDto: UpdatePermissionDto): Promise<Permission> {
    // Dữ liệu để cập nhật, chỉ lấy các trường được cung cấp
    const dataToUpdate: Partial<UpdatePermissionDto> = {}
    if (updatePermissionDto.action) dataToUpdate.action = updatePermissionDto.action
    if (updatePermissionDto.subject) dataToUpdate.subject = updatePermissionDto.subject
    if (updatePermissionDto.description) dataToUpdate.description = updatePermissionDto.description
    if (updatePermissionDto.category) dataToUpdate.category = updatePermissionDto.category

    return this.prisma.permission.update({
      where: { id },
      data: dataToUpdate
    })
  }

  async remove(id: number): Promise<Permission> {
    return this.prisma.permission.delete({
      where: { id }
    })
  }

  // Thêm các phương thức truy cập dữ liệu khác nếu cần
}
