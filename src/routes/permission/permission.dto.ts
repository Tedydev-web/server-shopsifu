import { createZodDto } from 'nestjs-zod'
import {
  CreatePermissionBodySchema,
  GetPermissionDetailResSchema,
  GetPermissionParamsSchema,
  GetPermissionsResSchema,
  UpdatePermissionBodySchema,
  CreatePermissionResSchema,
  UpdatePermissionResSchema,
  DeletePermissionResSchema,
  PermissionPaginationQuerySchema,
} from 'src/routes/permission/permission.model'

// Request DTOs
export class GetPermissionParamsDTO extends createZodDto(GetPermissionParamsSchema) {}
export class CreatePermissionBodyDTO extends createZodDto(CreatePermissionBodySchema) {}
export class UpdatePermissionBodyDTO extends createZodDto(UpdatePermissionBodySchema) {}
export class PermissionPaginationQueryDTO extends createZodDto(PermissionPaginationQuerySchema) {}

// Response DTOs
export class GetPermissionsResDTO extends createZodDto(GetPermissionsResSchema) {}
export class GetPermissionDetailResDTO extends createZodDto(GetPermissionDetailResSchema) {}
export class CreatePermissionResDTO extends createZodDto(CreatePermissionResSchema) {}
export class UpdatePermissionResDTO extends createZodDto(UpdatePermissionResSchema) {}
export class DeletePermissionResDTO extends createZodDto(DeletePermissionResSchema) {}
