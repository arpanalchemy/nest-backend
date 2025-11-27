import { Controller, Get, Param } from '@nestjs/common';
import { ApiOperation, ApiParam, ApiResponse } from '@nestjs/swagger';
import { BaseController } from '../common/base/base.controller';
import { User } from './user.entity';
import { CreateUserDto, UpdateUserDto } from './dto/user.dto';
import { UserService } from './user.service';

// Extend the BaseController using the factory function
@Controller('users')
export class UserController extends BaseController<User>(
  'User', // Entity name for Swagger
  CreateUserDto,
  UpdateUserDto,
  'users', // Route prefix (optional, defaults to entityName + 's')
) {
  constructor(private readonly userService: UserService) {
    super(userService);
  }

  // Add custom routes specific to User module here
  @Get('by-email/:email')
  @ApiOperation({ summary: 'Get user by email' })
  @ApiParam({ name: 'email', description: 'User email' })
  @ApiResponse({ status: 200, description: 'Return the user.' })
  @ApiResponse({ status: 404, description: 'User not found.' })
  async findByEmail(@Param('email') email: string) {
    return this.userService.findByEmail(email);
  }
}

