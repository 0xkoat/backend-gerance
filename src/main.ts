import 'dotenv/config';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';

// Webpack's HMR API — no official Node/Nest types for `module.hot` without
// pulling in @types/webpack-env just for this one file, so it's declared
// locally instead of left as the untyped `any` NestJS's own webpack-HMR
// boilerplate uses by default.
declare const module: {
  hot?: {
    accept(): void;
    dispose(callback: () => void): void;
  };
};

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

  try {
    await app.listen(process.env.PORT ?? 3000);
  } catch (error) {
    // The webpack --watch/HMR dev pipeline (webpack.config.js's
    // RunScriptWebpackPlugin + the `webpack/hot/poll?100` entry) briefly
    // spawns two `dist/main` processes on a cold start under a slow/
    // virtualized filesystem (observed reliably under WSL2, matching the
    // frontend dev server's own "Slow filesystem detected" note) — the
    // first to bind the port serves normally, the second used to crash
    // with an unhandled EADDRINUSE stack trace that looked like a real
    // failure. It isn't: exit this duplicate quietly instead. Any other
    // listen failure (a genuine port conflict, permissions, etc.) still
    // surfaces normally.
    if ((error as NodeJS.ErrnoException).code === 'EADDRINUSE') {
      console.warn(
        `[bootstrap] Port ${process.env.PORT ?? 3000} is already in use — ` +
          'another instance of this dev server is already listening (a known ' +
          'webpack --watch cold-start duplicate spawn, not a real error). ' +
          'Exiting this duplicate process quietly.',
      );
      await app.close();
      // app.close() alone doesn't drain this process's event loop (webpack's
      // HMR poll client and Nest's own internals keep handles open), so this
      // duplicate would otherwise sit idle forever instead of actually
      // exiting — force it, since nothing else in this process instance
      // matters once it's lost the race to bind the port.
      process.exit(0);
    }
    throw error;
  }

  if (module.hot) {
    module.hot.accept();
    module.hot.dispose(() => void app.close());
  }
}
void bootstrap();
