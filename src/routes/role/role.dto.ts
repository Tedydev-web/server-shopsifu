import { createZodDto } from 'nestjs-zod'
import {
  CreateRoleBodySchema,
  CreateRoleResSchema,
  GetRoleDetailResSchema,
  GetRoleParamsSchema,
  GetRolesResSchema,
  UpdateRoleBodySchema,
  UpdateRoleResSchema,
  DeleteRoleResSchema,
  RolePaginationQuerySchema,
} from 'src/routes/role/role.model'

// Request DTOs
export class GetRoleParamsDTO extends createZodDto(GetRoleParamsSchema) {}
export class CreateRoleBodyDTO extends createZodDto(CreateRoleBodySchema) {}
export class UpdateRoleBodyDTO extends createZodDto(UpdateRoleBodySchema) {}
export class RolePaginationQueryDTO extends createZodDto(RolePaginationQuerySchema) {}

// Response DTOs
export class GetRolesResDTO extends createZodDto(GetRolesResSchema) {}
export class GetRoleDetailResDTO extends createZodDto(GetRoleDetailResSchema) {}
export class CreateRoleResDTO extends createZodDto(CreateRoleResSchema) {}
export class UpdateRoleResDTO extends createZodDto(UpdateRoleResSchema) {}
export class DeleteRoleResDTO extends createZodDto(DeleteRoleResSchema) {}
