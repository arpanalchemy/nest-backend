import { Module } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { WinstonModule } from 'nest-winston';
import * as winston from 'winston';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { CognitoService, SecretsService } from 'alchemy-utilities';

@Module({
  imports: [
    CacheModule.register(),
    WinstonModule.forRoot({
      transports: [
        new winston.transports.Console({
          format: winston.format.simple(),
        }),
      ],
    }),
  ],
  providers: [
    AuthService, 
    CognitoService, 
    SecretsService
  ],
  controllers: [AuthController],
})
export class AuthModule {}