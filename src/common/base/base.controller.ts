import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Body,
  Type,
  UsePipes,
  ValidationPipe,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiBody } from '@nestjs/swagger';
import { ObjectLiteral } from 'typeorm';
import { BaseService } from './base.service';

// Mix-in function to generate a base controller class
export function BaseController<T extends ObjectLiteral>(
  entityName: string,
  createDto: Type<unknown>,
  updateDto: Type<unknown>,
  routePrefix?: string,
): Type<any> {
  const route = routePrefix || entityName.toLowerCase() + 's';

  // Dynamically create a Controller class
  @Controller(route)
  @ApiTags(entityName)
  @UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
  class BaseControllerHost {
    // Inject the concrete service that extends BaseService
    constructor(protected readonly service: BaseService<T>) {}

    @Post()
    @ApiOperation({ summary: `Create a new ${entityName}` })
    @ApiResponse({ status: 201, description: `The ${entityName} has been successfully created.` })
    @ApiResponse({ status: 400, description: 'Bad Request.' })
    @ApiBody({ type: createDto })
    create(@Body() createData: typeof createDto): Promise<T> {
      return this.service.create(createData as any);
    }

    @Get()
    @ApiOperation({ summary: `Get all ${entityName}s` })
    @ApiResponse({ status: 200, description: `Return all ${entityName}s.` })
    findAll(): Promise<T[]> {
      return this.service.findAll();
    }

    @Get(':id')
    @ApiOperation({ summary: `Get a ${entityName} by id` })
    @ApiParam({ name: 'id', description: `${entityName} id` })
    @ApiResponse({ status: 200, description: `Return the ${entityName}.` })
    @ApiResponse({ status: 404, description: `${entityName} not found.` })
    findOne(@Param('id') id: string): Promise<T | null> {
      return this.service.findById(id);
    }

    @Patch(':id')
    @ApiOperation({ summary: `Update a ${entityName}` })
    @ApiParam({ name: 'id', description: `${entityName} id` })
    @ApiResponse({ status: 200, description: `The ${entityName} has been successfully updated.` })
    @ApiResponse({ status: 404, description: `${entityName} not found.` })
    @ApiBody({ type: updateDto })
    update(@Param('id') id: string, @Body() updateData: typeof updateDto): Promise<T> {
      return this.service.update(id, updateData as any);
    }

    @Delete(':id')
    @HttpCode(HttpStatus.NO_CONTENT)
    @ApiOperation({ summary: `Delete a ${entityName}` })
    @ApiParam({ name: 'id', description: `${entityName} id` })
    @ApiResponse({ status: 204, description: `The ${entityName} has been successfully deleted.` })
    @ApiResponse({ status: 404, description: `${entityName} not found.` })
    remove(@Param('id') id: string): Promise<void> {
      return this.service.remove(id);
    }
  }

  return BaseControllerHost;
}

