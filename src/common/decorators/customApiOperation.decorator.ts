import { ApiOperation } from "@nestjs/swagger";

export function CustomApiOperation(options: {
  operationId?: string;
  summary?: string;
  deprecated?: boolean;
}) {
  return (
    // biome-ignore lint/suspicious/noExplicitAny: <explanation>
    target: any,
    key: string | symbol,
    descriptor: PropertyDescriptor
  ) => {
    ApiOperation({
      deprecated: !!options.deprecated,
      operationId: options.operationId || key.toString(),
      summary: options.summary || "",
    })(target, key, descriptor);

    return descriptor;
  };
}
