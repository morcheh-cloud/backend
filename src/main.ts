import { Logger, VersioningType } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import compression from "compression";
import { PORT } from "src/config/app.config";
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

  await app.listen(PORT, "0.0.0.0");
  logger.debug(`Application is running on: ${await app.getUrl()}`);
}
bootstrap();
