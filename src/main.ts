import { Logger, VersioningType } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import compression from "compression";
import { RedocModule, type RedocOptions } from "nestjs-redoc";
import { CORS_CONFIG, PORT } from "src/config/app.config";
import { AppModule } from "./app.module";

const logger = new Logger("main");

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableVersioning({
    defaultVersion: "1",
    type: VersioningType.URI,
  });

  // middlewares
  app.use(compression());

  if (CORS_CONFIG.enabled) {
    app.enableCors({ origin: CORS_CONFIG.origin });
  }

  // const {
  //   invalidCsrfTokenError, // This is provided purely for convenience if you plan on creating your own middleware.
  //   generateToken, // Use this in your routes to generate and provide a CSRF hash, along with a token cookie and token.
  //   validateRequest, // Also a convenience if you plan on making your own middleware.
  //   doubleCsrfProtection, // This is the default CSRF protection middleware.
  // } = doubleCsrf();
  // app.use(doubleCsrfProtection);

  const swaggerConfig = new DocumentBuilder()
    .setTitle("Morcheh")
    .setDescription("The Morcheh API description")
    .setVersion("1.0")
    .build();
  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup("swagger", app, document);

  const redocOptions: RedocOptions = {
    hideDownloadButton: false,
    hideHostname: false,
    sortPropsAlphabetically: true,
    title: "Morcheh API",
  };
  await RedocModule.setup("/redoc", app, document, redocOptions);

  await app.listen(PORT, "0.0.0.0");
  logger.debug(`Application is running on: ${await app.getUrl()}`);
  logger.debug(`Swagger is running on: ${await app.getUrl()}/swagger`);
  logger.debug(`Redoc is running on: ${await app.getUrl()}/redoc`);
}
bootstrap();
