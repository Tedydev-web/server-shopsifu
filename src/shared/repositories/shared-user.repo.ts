import { Injectable } from '@nestjs/common'
import { UserType } from 'src/shared/models/shared-user.model'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class SharedUserRepository {
  constructor(private readonly prismaService: PrismaService) {}

  async findUnique(uniqueObject: { email: string } | { id: number }): Promise<UserType | null> {
    if (!uniqueObject) {
      console.log('findUnique: uniqueObject là null hoặc undefined')
      return null
    }

    if ('id' in uniqueObject) {
      if (!uniqueObject.id) {
        console.log('findUnique: id là null hoặc undefined')
        return null
      }
      console.log(`findUnique: Đang tìm user với id=${uniqueObject.id}`)
    }

    if ('email' in uniqueObject) {
      if (!uniqueObject.email) {
        console.log('findUnique: email là null hoặc undefined')
        return null
      }
      console.log(`findUnique: Đang tìm user với email=${uniqueObject.email}`)
    }

    try {
      const user = await this.prismaService.user.findUnique({
        where: uniqueObject
      })
      console.log(`findUnique: Kết quả tìm kiếm: ${user ? 'Tìm thấy user' : 'Không tìm thấy user'}`)
      return user
    } catch (error) {
      console.error('findUnique: Lỗi khi tìm user:', error)
      return null
    }
  }
}
