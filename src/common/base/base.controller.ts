import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Body,
  Query,
  Type,
  UsePipes,
  ValidationPipe,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiParam,
  ApiBody,
  ApiQuery,
} from '@nestjs/swagger';
import { ObjectLiteral } from 'typeorm';
import { BaseService } from './base.service';
import { FindAllQueryDto, FindOneQueryDto } from './dto/query.dto';
import { PaginatedResponse } from './interfaces/paginated-response.interface';

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

    // Override this property in your controller to define default relations
    protected defaultRelations?: string[];

    @Post()
    @ApiOperation({ summary: `Create a new ${entityName}` })
    @ApiResponse({
      status: 201,
      description: `The ${entityName} has been successfully created.`,
    })
    @ApiResponse({ status: 400, description: 'Bad Request.' })
    @ApiBody({ type: createDto })
    create(@Body() createData: typeof createDto): Promise<T> {
      return this.service.create(createData as any);
    }

    @Get()
    @ApiOperation({
      summary: `Get all ${entityName}s with optional pagination, field selection, and relations`,
    })
    @ApiResponse({
      status: 200,
      description: `Return all ${entityName}s or paginated response.`,
    })
    @ApiQuery({
      name: 'page',
      required: false,
      type: Number,
      description: 'Page number (1-indexed)',
    })
    @ApiQuery({
      name: 'limit',
      required: false,
      type: Number,
      description: 'Number of items per page',
    })
    @ApiQuery({
      name: 'skip',
      required: false,
      type: Number,
      description: 'Skip number of items',
    })
    @ApiQuery({
      name: 'take',
      required: false,
      type: Number,
      description: 'Take number of items',
    })
    @ApiQuery({
      name: 'fields',
      required: false,
      type: String,
      description: 'Comma-separated fields to select',
    })
    @ApiQuery({
      name: 'search',
      required: false,
      type: String,
      description: 'Search term to search across all string fields',
    })
    @ApiQuery({
      name: 'sortBy',
      required: false,
      type: String,
      description: 'Field to sort by',
    })
    @ApiQuery({
      name: 'order',
      required: false,
      enum: ['ASC', 'DESC'],
      description: 'Sort order',
    })
    findAll(
      @Query() queryDto: FindAllQueryDto,
    ): Promise<PaginatedResponse<T> | T[]> {
      // Use default relations from controller or pass undefined
      return this.service.findAllWithOptions(queryDto, this.defaultRelations);
    }

    @Get(':id')
    @ApiOperation({
      summary: `Get a ${entityName} by id with optional field selection and relations`,
    })
    @ApiParam({ name: 'id', description: `${entityName} id` })
    @ApiResponse({ status: 200, description: `Return the ${entityName}.` })
    @ApiResponse({ status: 404, description: `${entityName} not found.` })
    @ApiQuery({
      name: 'fields',
      required: false,
      type: String,
      description: 'Comma-separated fields to select',
    })
    findOne(
      @Param('id') id: string,
      @Query() queryDto: FindOneQueryDto,
    ): Promise<T | null> {
      // Use default relations from controller or pass undefined
      return this.service.findById(id, queryDto, this.defaultRelations);
    }

    @Patch(':id')
    @ApiOperation({ summary: `Update a ${entityName}` })
    @ApiParam({ name: 'id', description: `${entityName} id` })
    @ApiResponse({
      status: 200,
      description: `The ${entityName} has been successfully updated.`,
    })
    @ApiResponse({ status: 404, description: `${entityName} not found.` })
    @ApiBody({ type: updateDto })
    update(
      @Param('id') id: string,
      @Body() updateData: typeof updateDto,
    ): Promise<T> {
      return this.service.update(id, updateData as any);
    }

    @Delete(':id')
    @HttpCode(HttpStatus.NO_CONTENT)
    @ApiOperation({ summary: `Delete a ${entityName}` })
    @ApiParam({ name: 'id', description: `${entityName} id` })
    @ApiResponse({
      status: 204,
      description: `The ${entityName} has been successfully deleted.`,
    })
    @ApiResponse({ status: 404, description: `${entityName} not found.` })
    remove(@Param('id') id: string): Promise<void> {
      return this.service.remove(id);
    }
  }

  return BaseControllerHost;
}

