import {
  FindManyOptions,
  Repository,
  DeepPartial,
  FindOneOptions,
  ObjectLiteral,
  FindOptionsWhere,
} from 'typeorm';

export abstract class BaseService<T extends ObjectLiteral> {
  // Inject the specific repository into the constructor of the concrete service
  constructor(protected readonly repository: Repository<T>) {}

  // --- Read Operations ---
  async findAll(options?: FindManyOptions<T>): Promise<T[]> {
    return this.repository.find(options);
  }

  async findOne(options: FindOneOptions<T>): Promise<T | null> {
    return this.repository.findOne(options);
  }

  async findById(id: string | number): Promise<T | null> {
    return this.repository.findOne({
      where: { id } as unknown as FindOptionsWhere<T>,
    });
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
