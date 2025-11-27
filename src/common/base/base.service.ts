import {
  FindManyOptions,
  Repository,
  DeepPartial,
  FindOneOptions,
  ObjectLiteral,
  FindOptionsWhere,
  ILike,
  Or,
} from 'typeorm';
import { FindAllQueryDto, FindOneQueryDto } from './dto/query.dto';
import { PaginatedResponse } from './interfaces/paginated-response.interface';

export abstract class BaseService<T extends ObjectLiteral> {
  // Inject the specific repository into the constructor of the concrete service
  constructor(protected readonly repository: Repository<T>) {}

  // --- Read Operations ---
  async findAll(options?: FindManyOptions<T>): Promise<T[]> {
    return this.repository.find(options);
  }

  /**
   * Find all entities with pagination, field selection, search, and relations support
   */
  async findAllWithOptions(
    queryDto?: FindAllQueryDto,
    relations?: string[],
  ): Promise<PaginatedResponse<T> | T[]> {
    // If search is provided, use query builder for better control
    if (queryDto?.search) {
      return this.findAllWithSearch(queryDto, relations);
    }

    const options = this.buildFindManyOptions(queryDto, relations);
    const { skip, take } = options;

    // If pagination is requested, return paginated response
    if (
      skip !== undefined ||
      take !== undefined ||
      queryDto?.page ||
      queryDto?.limit
    ) {
      const [data, total] = await this.repository.findAndCount(options);
      const page =
        queryDto?.page || (skip && take ? Math.floor(skip / take) + 1 : 1);
      const limit = queryDto?.limit || take || queryDto?.take || 10;
      const totalPages = Math.ceil(total / limit);

      return {
        data,
        meta: {
          total,
          page,
          limit,
          totalPages,
          hasNextPage: page < totalPages,
          hasPreviousPage: page > 1,
        },
      };
    }

    // Otherwise return all data
    const data = await this.repository.find(options);
    return data;
  }

  /**
   * Find all with search using query builder
   */
  private async findAllWithSearch(
    queryDto: FindAllQueryDto,
    relations?: string[],
  ): Promise<PaginatedResponse<T> | T[]> {
    const searchTerm = `%${queryDto.search}%`;
    const metadata = this.repository.metadata;
    const alias = 'entity'; // Use a standard alias for query builder

    // Get all string-type columns
    const stringColumns = metadata.columns
      .filter((col) => {
        // Check if column is a string type by checking the type property
        const type = col.type;
        const typeString = String(type).toLowerCase();
        
        // Check various string type representations
        return (
          type === String ||
          typeString.includes('varchar') ||
          typeString.includes('text') ||
          typeString.includes('string') ||
          typeString === 'character varying' ||
          ['varchar', 'text', 'string', 'character varying'].some(
            (t) => typeString === t,
          )
        );
      })
      .map((col) => col.propertyName)
      .filter((name) => name !== 'id'); // Exclude id from search

    if (stringColumns.length === 0) {
      // No string columns found, return without search
      return this.findAllWithOptions(
        { ...queryDto, search: undefined },
        relations,
      );
    }

    // Build query builder with proper alias
    const queryBuilder = this.repository.createQueryBuilder(alias);

    // Add search conditions using ILIKE for case-insensitive search
    if (stringColumns.length === 1) {
      queryBuilder.where(`${alias}.${stringColumns[0]} ILIKE :search`, {
        search: searchTerm,
      });
    } else {
      const conditions = stringColumns
        .map((col) => `${alias}.${col} ILIKE :search`)
        .join(' OR ');
      queryBuilder.where(`(${conditions})`, { search: searchTerm });
    }

    // Add relations
    if (relations && relations.length > 0) {
      relations.forEach((relation) => {
        queryBuilder.leftJoinAndSelect(`${alias}.${relation}`, relation);
      });
    }

    // Add field selection
    if (queryDto?.fields) {
      const fields = queryDto.fields.split(',').map((f) => f.trim());
      queryBuilder.select(
        fields.map((field) => `${alias}.${field}`),
      );
    }

    // Add sorting
    if (queryDto?.sortBy) {
      queryBuilder.orderBy(
        `${alias}.${queryDto.sortBy}`,
        queryDto.order || 'ASC',
      );
    }

    // Handle pagination
    const skip =
      queryDto?.skip !== undefined
        ? queryDto.skip
        : queryDto?.page && queryDto?.limit
          ? (queryDto.page - 1) * queryDto.limit
          : undefined;
    const take = queryDto?.take || queryDto?.limit;

    if (skip !== undefined) {
      queryBuilder.skip(skip);
    }
    if (take !== undefined) {
      queryBuilder.take(take);
    }

    // Execute query
    if (
      skip !== undefined ||
      take !== undefined ||
      queryDto?.page ||
      queryDto?.limit
    ) {
      const [data, total] = await queryBuilder.getManyAndCount();
      const page =
        queryDto?.page || (skip && take ? Math.floor(skip / take) + 1 : 1);
      const limit = queryDto?.limit || take || 10;
      const totalPages = Math.ceil(total / limit);

      return {
        data,
        meta: {
          total,
          page,
          limit,
          totalPages,
          hasNextPage: page < totalPages,
          hasPreviousPage: page > 1,
        },
      };
    }

    const data = await queryBuilder.getMany();
    return data;
  }

  async findOne(options?: FindOneOptions<T>): Promise<T | null> {
    return this.repository.findOne(options || {});
  }

  /**
   * Find one entity with field selection and relations support
   */
  async findOneWithOptions(
    id: string | number,
    queryDto?: FindOneQueryDto,
    relations?: string[],
  ): Promise<T | null> {
    const options = this.buildFindOneOptions(queryDto, relations);
    options.where = { id } as unknown as FindOptionsWhere<T>;
    return this.repository.findOne(options);
  }

  async findById(
    id: string | number,
    queryDto?: FindOneQueryDto,
    relations?: string[],
  ): Promise<T | null> {
    if (queryDto || relations) {
      return this.findOneWithOptions(id, queryDto, relations);
    }
    return this.repository.findOne({
      where: { id } as unknown as FindOptionsWhere<T>,
    });
  }

  /**
   * Build FindManyOptions from query DTO
   */
  private buildFindManyOptions(
    queryDto?: FindAllQueryDto,
    relations?: string[],
  ): FindManyOptions<T> {
    const options: FindManyOptions<T> = {};

    // Pagination
    if (queryDto?.page && queryDto?.limit) {
      options.skip = (queryDto.page - 1) * queryDto.limit;
      options.take = queryDto.limit;
    } else {
      if (queryDto?.skip !== undefined) {
        options.skip = queryDto.skip;
      }
      if (queryDto?.take !== undefined) {
        options.take = queryDto.take;
      }
      if (queryDto?.limit !== undefined) {
        options.take = queryDto.limit;
      }
    }

    // Field selection
    if (queryDto?.fields) {
      const fields = queryDto.fields.split(',').map((f) => f.trim());
      options.select = fields as (keyof T)[];
    }

    // Relations (from parameter, not query)
    if (relations && relations.length > 0) {
      options.relations = relations;
    }

    // Note: Search is handled separately in findAllWithSearch method using query builder
    // This method is only called when search is not present

    // Sorting
    if (queryDto?.sortBy) {
      options.order = {
        [queryDto.sortBy]: queryDto.order || 'ASC',
      } as any;
    }

    return options;
  }

  /**
   * Build FindOneOptions from query DTO
   */
  private buildFindOneOptions(
    queryDto?: FindOneQueryDto,
    relations?: string[],
  ): FindOneOptions<T> {
    const options: FindOneOptions<T> = {};

    // Field selection
    if (queryDto?.fields) {
      const fields = queryDto.fields.split(',').map((f) => f.trim());
      options.select = fields as (keyof T)[];
    }

    // Relations (from parameter, not query)
    if (relations && relations.length > 0) {
      options.relations = relations;
    }

    return options;
  }

  // --- Write Operations ---
  async create(data: DeepPartial<T>): Promise<T> {
    const entity = this.repository.create(data);
    return this.repository.save(entity);
  }

  async update(id: string | number, data: DeepPartial<T>): Promise<T> {
    // TypeORM's update method has complex type requirements, so we use a type assertion
    // This is safe because T extends ObjectLiteral
    await this.repository.update(id, data as any);
    const updated = await this.findById(id);
    if (!updated) {
      throw new Error(`Entity with id ${id} not found after update`);
    }
    return updated;
  }

  async remove(id: string | number): Promise<void> {
    await this.repository.delete(id);
  }

  async delete(id: string | number): Promise<void> {
    await this.remove(id);
  }
}
