import { exec } from "node:child_process";
import { promisify } from "node:util";

import { Client } from "pg";

const execAsync = promisify(exec);

async function main() {
	const client = new Client({
		database: "postgres",
		host: "localhost",
		password: "postgres",
		user: "postgres",
	});

	await client.connect();

	// Run ansible-doc to get JSON list of modules
	const { stdout: ansibleListRaw } = await execAsync("ansible-doc -j -l");
	const modules = JSON.parse(ansibleListRaw);
	const moduleNames = Object.keys(modules);
	let counter = 1;
	const size = moduleNames.length;

	for (const moduleName of moduleNames) {

		const { stdout: ansibleDocRaw } = await execAsync(
			`ansible-doc -j ${moduleName}`,
		);
		const name = JSON.parse(ansibleDocRaw);
		const schema = name[moduleName];
		const isOfficial = schema?.doc?.is_official || false;
		const description = schema?.doc?.description?.[0] || '';

		const isExistQuery = await client.query(
			`SELECT EXISTS (
				SELECT 1 FROM "public"."play_book" WHERE "name" = $1
			)`,
			[moduleName]
		);


		const exist =  isExistQuery.rows[0].exists;

		if (exist) {
			// update
			await client.query(
				`UPDATE "public"."play_book" SET "description" = $1, "type" = $2, "schema" = $3 WHERE "name" = $4`,
				[
					description,
					isOfficial ? "official" : "community",
					schema,
					moduleName
				]
			);
		} else {
			// insert
			await client.query(
			`INSERT INTO "public"."play_book" ("name", "description", "type", "schema") 
			 VALUES ($1, $2, $3, $4)`,
			[
				moduleName,
				description,
				isOfficial ? "official" : "community",
				schema, // pg will store it as JSON automatically
			]
		);
		}

		console.log(`Processed module: ${moduleName.padEnd(60)}`, `(${counter++}/${size})`);
	}

}

main();
