import { Injectable, Inject } from '@nestjs/common'
import { UserRepository } from './user.repository'
import { CreateUserDto, UpdateUserDto } from './user.dto'
import { User } from '@prisma/client'
import { UserError } from './user.error'
import { HashingService } from 'src/shared/services/hashing.service'
import { HASHING_SERVICE } from 'src/shared/constants/injection.tokens'

@Injectable()
export class UserService {
  constructor(
    private readonly userRepository: UserRepository,
    @Inject(HASHING_SERVICE) private readonly hashingService: HashingService
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const existingUser = await this.userRepository.findByEmail(createUserDto.email)
    if (existingUser) {
      throw UserError.AlreadyExists(createUserDto.email)
    }

    const { password, ...rest } = createUserDto
    const hashedPassword = await this.hashingService.hash(password)

    const userData: any = {
      ...rest,
      password: hashedPassword
    }

    return this.userRepository.create(userData)
  }

  async findAll(): Promise<User[]> {
    return this.userRepository.findAll()
  }

  async findOne(id: number): Promise<User> {
    const user = await this.userRepository.findById(id)
    if (!user) {
      throw UserError.NotFound()
    }
    return user
  }

  async update(id: number, updateUserDto: UpdateUserDto): Promise<User> {
    await this.findOne(id) // check existence
    const dataToUpdate: any = { ...updateUserDto }

    if (updateUserDto.password) {
      dataToUpdate.password = await this.hashingService.hash(updateUserDto.password)
    }

    return this.userRepository.update(id, dataToUpdate)
  }

  async remove(id: number): Promise<User> {
    await this.findOne(id) // check existence
    return this.userRepository.remove(id)
  }
}
