import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export async function runCommand(cmd: string, args: string[] = []) {
  try {
    const { stdout, stderr } = await execFileAsync(cmd, args);
    return {
      stderr,
      stdout,
    };
  } catch (error) {
    console.error(`❌ Error running command: ${cmd}`, error);
    throw error;
  }
}
