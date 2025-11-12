import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { CognitoExceptionFilter } from 'alchemy-utilities';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // --- Global Filters ---
  app.useGlobalFilters(new CognitoExceptionFilter());

  // --- Swagger Configuration ---
  const config = new DocumentBuilder()
    .setTitle('Alchemy Platform API')
    .setDescription('API documentation for the Alchemy microservices platform.')
    .setVersion('1.0.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'Authorization',
        description: 'Enter JWT token',
        in: 'header',
      },
      'access-token',
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true, // keeps JWT token between page reloads
    },
  });

  const port = process.env.PORT ?? 3000;
  await app.listen(port);
  console.log(`🚀 Server running on http://localhost:${port}`);
  console.log(`📘 Swagger docs available at http://localhost:${port}/api/docs`);
}

bootstrap();
