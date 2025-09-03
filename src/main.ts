import { Logger, ValidationPipe, VersioningType } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import compression from "compression";
import { CORS_CONFIG, PORT } from "src/config/app.config";
import { AppModule } from "./app.module";

const logger = new Logger("main");

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableVersioning({
    defaultVersion: "1",
    type: VersioningType.URI,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      // forbidNonWhitelisted: true,
    })
  );

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
    .setDescription("The Morcheh API documentation")
    .setVersion("1.0")
    .setContact(
      "Support Team",
      "https://morcheh.io/support",
      "support@morcheh.io"
    )
    .setLicense("MIT", "https://opensource.org/licenses/MIT")
    .addBearerAuth()
    // .addBearerAuth(
    //   {
    //     bearerFormat: "JWT",
    //     description: "Enter JWT token",
    //     scheme: "bearer",
    //     type: "http",
    //   },
    //   "JWT-auth"
    // )
    .addServer("http://127.0.0.1:3000", "Local development")
    .addServer("https://api.morcheh.io", "Production server")
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig, {
    deepScanRoutes: true,
  });

  SwaggerModule.setup("swagger", app, document, {
    customCss: `
    .swagger-ui .topbar { display: none }
  	`,
    customSiteTitle: "Morcheh API Docs",
    swaggerOptions: {
      authAction: {
        "JWT-auth": {
          name: "JWT-auth",
          schema: {
            bearerFormat: "JWT",
            scheme: "bearer",
            type: "http",
          },
          value: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", // <-- put your token here
        },
      },
      deepLinking: "true",
      defaultModelsExpandDepth: -1,
      displayRequestDuration: "true",
      operationsSorter: "alpha",
      persistAuthorization: true,
      tagsSorter: "alpha",
    },
  });

  await app.listen(PORT, "0.0.0.0");

  logger.debug(`Application is running on: ${await app.getUrl()}`);
  logger.debug(`Swagger is running on: ${await app.getUrl()}/swagger`);
}
bootstrap();
