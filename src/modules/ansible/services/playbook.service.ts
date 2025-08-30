import { execFile } from "node:child_process";
import os from "node:os";
import { promisify } from "node:util";
import { Injectable, Logger, OnModuleInit } from "@nestjs/common";
import { InjectDataSource } from "@nestjs/typeorm";
import { PlaybookRepository } from "src/modules/ansible/repositories/playbook.repository";
import type { DataSource } from "typeorm";

const execFileAsync = promisify(execFile);

type AnyRecord = Record<string, any>;

// lightweight p-limit (no deps)
function pLimit(concurrency: number) {
  let active = 0;
  const queue: Array<() => void> = [];
  const next = () => {
    if (active >= concurrency || queue.length === 0) return;
    active++;
    const run = queue.shift();
    if (run) run();
  };
  return <T>(fn: () => Promise<T>) =>
    new Promise<T>((resolve, reject) => {
      const task = () =>
        fn()
          .then(resolve, reject)
          .finally(() => {
            active--;
            next();
          });
      queue.push(task);
      next();
    });
}

async function withRetry<T>(
  fn: (attempt: number) => Promise<T>,
  { retries = 2, baseMs = 250 }: { retries?: number; baseMs?: number } = {}
): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn(attempt);
    } catch (err) {
      lastErr = err;
      if (attempt === retries) break;
      const jitter = Math.floor(Math.random() * 100);
      const delay = baseMs * 2 ** attempt + jitter;
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

const DEFAULT_CONCURRENCY = Math.max(4, Math.min(16, os.cpus()?.length || 8));
const CONCURRENCY = DEFAULT_CONCURRENCY;
const MAX_BUFFER = 16 * 1024 * 1024; // 16MB, ansible-doc output can be large

@Injectable()
export class PlaybookService implements OnModuleInit {
  private readonly logger = new Logger(PlaybookService.name);

  private ansibleModuleSize = 0;
  private updatedModulesCount = 0;

  constructor(
    @InjectDataSource()
    private dataSource: DataSource,
    private playbookRepository: PlaybookRepository
  ) {}

  onModuleInit() {
    this.init();
  }

  async init() {
    const count = await this.playbookRepository.count();
    if (count === 0) {
      this.sync();
    }
  }

  private async upsertModule(input: {
    name: string;
    description: string;
    type: "official" | "community";
    schema: AnyRecord;
  }) {
    const sql = `
      INSERT INTO public.play_book (name, description, type, schema)
      VALUES ($1, $2, $3, $4::jsonb)
      ON CONFLICT (name) DO UPDATE
      SET description = EXCLUDED.description,
          type        = EXCLUDED.type,
          schema      = EXCLUDED.schema
    `;
    // node-postgres under TypeORM will serialize objects; cast as jsonb for clarity
    await this.dataSource.query(sql, [
      input.name,
      input.description,
      input.type,
      JSON.stringify(input.schema),
    ]);
  }

  async sync(): Promise<{ total: number; succeeded: number; failed: number }> {
    this.logger.log(`Starting ansible sync with concurrency=${CONCURRENCY}…`);

    const { stdout: listStdout } = await execFileAsync(
      "ansible-doc",
      ["-j", "-l"],
      { maxBuffer: MAX_BUFFER }
    );
    const modules: AnyRecord = JSON.parse(listStdout);
    const moduleNames = Object.keys(modules);

    this.logger.log(`Found ${moduleNames.length} modules.`);
    this.ansibleModuleSize = moduleNames.length;

    // 2) run tasks with concurrency + retries
    const limit = pLimit(CONCURRENCY);
    let processed = 0;
    let failures = 0;
    const total = moduleNames.length;

    const tasks = moduleNames.map((moduleName) =>
      limit(async () => {
        try {
          const schema = await withRetry(async () => {
            const { stdout } = await execFileAsync(
              "ansible-doc",
              ["-j", moduleName],
              { maxBuffer: MAX_BUFFER }
            );
            const parsed: AnyRecord = JSON.parse(stdout);
            const s = parsed?.[moduleName];
            if (!s) throw new Error(`No JSON payload for ${moduleName}`);
            return s;
          });

          const isOfficial = moduleName.includes("community");
          const description: string = schema?.doc?.description?.[0] ?? "";

          await this.upsertModule({
            description,
            name: moduleName,
            schema,
            type: isOfficial ? "community" : "official",
          });

          const doneCount = ++processed;
          this.updatedModulesCount = doneCount;
          if (doneCount % 25 === 0 || doneCount === total) {
            this.logger.log(`Progress: ${doneCount}/${total}`);
          }
        } catch (err: unknown) {
          failures++;
          const msg =
            err instanceof Error
              ? err.message
              : typeof err === "string"
              ? err
              : "Unknown error";
          this.logger.error(`Failed "${moduleName}": ${msg}`);
        }
      })
    );

    await Promise.all(tasks);

    this.logger.log(
      `Ansible sync complete. ok=${
        processed - failures
      }, failed=${failures}, total=${total}`
    );

    return { failed: failures, succeeded: total - failures, total };
  }

  getSyncStatus() {
    return {
      total: this.ansibleModuleSize,
      updated: this.updatedModulesCount,
    };
  }
}
