import { Injectable } from '@nestjs/common'
import { RoleType } from 'src/shared/models/shared-role.model'
import { RoleName } from 'src/shared/constants/role.constant'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class RolesService {
  private clientRoleId: number | null = null

  constructor(private readonly prismaService: PrismaService) {}

  async getRoleById(id: number) {
    return this.prismaService.role.findUnique({
      where: { id },
    })
  }

  async getClientRoleId() {
    if (this.clientRoleId) {
      return this.clientRoleId
    }
    const role: RoleType = await this.prismaService.$queryRaw`
      SELECT * FROM "Role" WHERE name = ${RoleName.Client} AND "deletedAt" IS NULL LIMIT 1;
    `.then((res: RoleType[]) => {
      if (res.length === 0) {
        throw new Error('Client role not found')
      }
      return res[0]
    })

    this.clientRoleId = role.id
    return role.id
  }
}
