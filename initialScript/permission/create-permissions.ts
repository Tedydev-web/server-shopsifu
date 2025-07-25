import { NestFactory } from '@nestjs/core'
import { AppModule } from 'src/app.module'
import { HTTPMethod, RoleName } from 'src/shared/constants/role.constant'
import { PrismaService } from 'src/shared/services/prisma.service'

const SellerModule = [
  'AUTH',
  'MEDIA',
  'MANAGE-PRODUCT',
  'PRODUCT-TRANSLATION',
  'PROFILE',
  'CART',
  'ORDERS',
  'REVIEWS',
  'DISCOUNTS'
]
const ClientModule = ['AUTH', 'MEDIA', 'PROFILE', 'CART', 'ORDERS', 'REVIEWS', 'DISCOUNTS']
const prisma = new PrismaService()

async function bootstrap() {
  const app = await NestFactory.create(AppModule)
  await app.listen(3010)
  const server = app.getHttpAdapter().getInstance()
  const router = server.router
  const permissionsInDb = await prisma.permission.findMany({
    where: {
      deletedAt: null
    }
  })
  const availableRoutes: { path: string; method: keyof typeof HTTPMethod; name: string; module: string }[] =
    router.stack
      .map((layer) => {
        if (layer.route) {
          const path = layer.route?.path
          const method = String(layer.route?.stack[0].method).toUpperCase() as keyof typeof HTTPMethod
          const moduleName = String(path.split('/')[1]).toUpperCase()
          return {
            path,
            method,
            name: method + ' ' + path,
            module: moduleName
          }
        }
      })
      .filter((item) => item !== undefined)
  // Tạo object permissionInDbMap với key là [method-path]
  const permissionInDbMap: Record<string, (typeof permissionsInDb)[0]> = permissionsInDb.reduce((acc, item) => {
    acc[`${item.method}-${item.path}`] = item
    return acc
  }, {})
  // Tạo object availableRoutesMap với key là [method-path]
  const availableRoutesMap: Record<string, (typeof availableRoutes)[0]> = availableRoutes.reduce((acc, item) => {
    acc[`${item.method}-${item.path}`] = item
    return acc
  }, {})

  // Tìm permissions trong database mà không tồn tại trong availableRoutes
  const permissionsToDelete = permissionsInDb.filter((item) => {
    return !availableRoutesMap[`${item.method}-${item.path}`]
  })
  // Xóa permissions không tồn tại trong availableRoutes
  if (permissionsToDelete.length > 0) {
    const deleteResult = await prisma.permission.deleteMany({
      where: {
        id: {
          in: permissionsToDelete.map((item) => item.id)
        }
      }
    })
    console.log('Deleted permissions:', deleteResult.count)
  } else {
    console.log('No permissions to delete')
  }
  // Tìm routes mà không tồn tại trong permissionsInDb
  const routesToAdd = availableRoutes.filter((item) => {
    return !permissionInDbMap[`${item.method}-${item.path}`]
  })
  // Thêm các routes này dưới dạng permissions database
  if (routesToAdd.length > 0) {
    const validHTTPMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
    const permissionsData = routesToAdd.map((item) => ({
      method: item.method,
      path: item.path,
      name: item.name,
      module: item.module
    }))
    // Lọc bỏ các permission có method không hợp lệ (ví dụ: 'ACL')
    const filteredPermissions = permissionsData.filter((p) => validHTTPMethods.includes(p.method))

    const permissionsToAdd = await prisma.permission.createMany({
      data: filteredPermissions,
      skipDuplicates: true
    })
    console.log('Added permissions:', permissionsToAdd.count)
  } else {
    console.log('No permissions to add')
  }

  // Lấy lại permissions trong database sau khi thêm mới (hoặc bị xóa)
  const updatedPermissionsInDb = await prisma.permission.findMany({
    where: {
      deletedAt: null
    }
  })
  const adminPermissionIds = updatedPermissionsInDb.map((item) => ({ id: item.id }))
  const sellerPermissionIds = updatedPermissionsInDb
    .filter((item) => SellerModule.includes(item.module))
    .map((item) => ({ id: item.id }))
  const clientPermissionIds = updatedPermissionsInDb
    .filter((item) => ClientModule.includes(item.module))
    .map((item) => ({ id: item.id }))

  await Promise.all([
    updateRole(adminPermissionIds, RoleName.Admin),
    updateRole(sellerPermissionIds, RoleName.Seller),
    updateRole(clientPermissionIds, RoleName.Client)
  ])
  process.exit(0)
}

const updateRole = async (permissionIds: { id: string }[], roleName: string) => {
  // Cập nhật lại các permissions trong Admin Role
  const role = await prisma.role.findFirstOrThrow({
    where: {
      name: roleName,
      deletedAt: null
    }
  })
  await prisma.role.update({
    where: {
      id: role.id
    },
    data: {
      permissions: {
        set: permissionIds
      }
    }
  })
}
bootstrap()
