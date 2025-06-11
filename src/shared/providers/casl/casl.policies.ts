import { Type } from '@nestjs/common'
import { Action, AppAbility, Subjects } from './casl-ability.factory'
import { IPolicyHandler } from './casl.types'
import { PrismaService } from '../prisma/prisma.service'
import { subject as caslSubject } from '@casl/ability'
import { Request } from 'express'
import { getSubjectName } from 'src/shared/utils/get-subject-name.util'

interface CheckAbilityOptions {
  action: Action
  subject: Subjects
  idFromParam?: string // e.g. 'userId' if the URL is /users/:userId
  subjectName?: string // The name of the subject to create with caslSubject
}

export class CheckAbilityPolicyHandler implements IPolicyHandler {
  constructor(
    private readonly options: CheckAbilityOptions,
    private readonly prisma: PrismaService
  ) {}

  async handle(ability: AppAbility, request: Request): Promise<boolean> {
    const { action, subject: subjectType, idFromParam, subjectName } = this.options

    if (idFromParam && request.params[idFromParam]) {
      const id = +request.params[idFromParam]
      const modelName = getSubjectName(subjectType).toLowerCase()

      if (!this.prisma[modelName]) {
        return false // Or throw an error
      }

      const record = await this.prisma[modelName].findUnique({ where: { id } })

      if (!record) {
        return false // Or throw a NotFoundException
      }

      // Use caslSubject to create a subject object with the correct type
      const subject = caslSubject(subjectName || getSubjectName(subjectType), record)
      return ability.can(action, subject)
    }

    return ability.can(action, subjectType)
  }
}

// Helper function to make using the handler cleaner in controllers
export function CheckAbilities(...requirements: CheckAbilityOptions[]): Type<IPolicyHandler>[] {
  return requirements.map((requirement) => {
    class Handler extends CheckAbilityPolicyHandler {
      constructor(prisma: PrismaService) {
        super(requirement, prisma)
      }
    }
    // We need to change the name of the class dynamically so that NestJS can differentiate them
    // when providing them in the guard.
    Object.defineProperty(Handler, 'name', {
      value: `CheckAbility${requirement.action}${getSubjectName(requirement.subject)}PolicyHandler`,
      writable: false
    })
    return Handler
  })
}
