import { createZodDto } from 'nestjs-zod'
import {
  CreateRoleBodySchema,
  CreateRoleResSchema,
  GetRoleDetailResSchema,
  GetRoleParamsSchema,
  GetRolesQuerySchema,
  GetRolesResSchema,
  UpdateRoleBodySchema,
} from 'src/routes/role/role.model'

export class GetRolesResDTO extends createZodDto(GetRolesResSchema) {}

export class GetRoleParamsDTO extends createZodDto(GetRoleParamsSchema) {}

export class GetRoleDetailResDTO extends createZodDto(GetRoleDetailResSchema) {}

export class CreateRoleBodyDTO extends createZodDto(CreateRoleBodySchema) {}

export class CreateRoleResDTO extends createZodDto(CreateRoleResSchema) {}

export class UpdateRoleBodyDTO extends createZodDto(UpdateRoleBodySchema) {}

export class GetRolesQueryDTO extends createZodDto(GetRolesQuerySchema) {}
