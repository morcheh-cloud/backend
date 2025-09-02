import { InternalServerErrorException } from "@nestjs/common";
import { SelectQueryBuilder } from "typeorm";

export interface IPagination {
  skip?: number;
  take?: number;
}

export function Paginate(page: number, limit: number): IPagination {
  return {
    skip: page * limit,
    take: limit,
  };
}

export async function PaginateQuery<T>(
  qb: SelectQueryBuilder<any>,
  params: { page: number; limit?: number; mode?: "legacy" | "modern" }
): Promise<[T[], number]> {
  const limit = params?.limit || 8;
  const mode = params?.mode || "legacy";
  const page = params?.page || 1;

  if (page < 0) {
    throw new InternalServerErrorException("page must be  > -1 ");
  }

  if (mode === "legacy") {
    qb.limit(limit).offset(page * limit);
  } else if (mode === "modern") {
    qb.take(limit).skip(page * limit);
  } else {
    throw new InternalServerErrorException("mode is not valid");
  }

  return await qb.getManyAndCount();
}
