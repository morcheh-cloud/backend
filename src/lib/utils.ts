import yaml from "js-yaml"
import { v7 as uuidv7 } from "uuid"

export function EnsureIsArray(input: unknown) {
	if (Array.isArray(input)) {
		return input
	} else if (input) {
		return [input]
	}
	return [] // Default return for null or undefined input
}

export function jsonToYaml(jsonObj: unknown): string {
	return yaml.dump(jsonObj)
}

export function Sleep(ms: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, ms))
}

export function GenUUID(): string {
	return uuidv7()
}
