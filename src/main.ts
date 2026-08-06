import 'dotenv/config';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';

declare const module: any;

// Composition root: wires global middleware/guards/pipes onto the Nest app
// before it starts listening. Order matters here: helmet/cookieParser/CORS
// must be applied before routes are hit, and the global prefix must be set
// before Nest resolves any controller path.
async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(
    helmet({
      hsts: {
        maxAge: 63072000, //2 years in seconds
        includeSubDomains: true,
        preload: true,
      },
    }),
  );

  app.use(cookieParser());

  // credentials: true is required for the browser to send/accept the
  // httpOnly refresh-token cookie; a wildcard origin is incompatible with
  // that, so FRONTEND_URL must be set to the frontend's exact origin.
  app.enableCors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  });

  app.setGlobalPrefix('api');

  app.useGlobalFilters(new AllExceptionsFilter());

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }),
  );

  await app.listen(process.env.PORT ?? 3000);

  if (module.hot) {
    module.hot.accept();
    module.hot.dispose(() => app.close());
  }
}
bootstrap();
