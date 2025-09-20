import { Injectable, NotFoundException } from "@nestjs/common"
import { SaveDirectoryPayload } from "src/modules/directory/DTOs/directory.dto"
import { Directory, DirectoryType } from "src/modules/directory/entities/directory.entity"
import { DirectoryRepository } from "src/modules/directory/repositories/directory.repository"
import { IsNull } from "typeorm"

@Injectable()
export class DirectoryService {
	constructor(private directoryRepository: DirectoryRepository) {}

	private buildTree(list: Directory[]) {
		const map = new Map<string, Directory & { children: Directory[] }>()

		// there is just one root
		const root: Directory | undefined = list.find(item => item.parent === null)
		if (!root) {
			throw new Error("Root directory not found")
		}

		for (const item of list) {
			map.set(item.id, { ...item, children: [] } as unknown as Directory & { children: Directory[] })
		}
		for (const item of list) {
			if (item.parent) {
				const parent = map.get(item.parent.id)
				const child = map.get(item.id)
				if (parent && child) {
					parent.children.push(child)
				}
			}
		}

		return map.get(root.id)
	}

	private async getOrCreateRootDirectory(workspaceId: string, type: DirectoryType) {
		let rootDirectory = await this.directoryRepository.findOne({
			where: {
				parent: IsNull(),
				type,
				workspace: { id: workspaceId },
			},
		})

		if (!rootDirectory) {
			rootDirectory = await this.directoryRepository.createAndSave({
				isDeletable: false,
				isEditable: false,
				isHidden: true,
				isLocked: true,
				name: "root",
				type,
				workspace: { id: workspaceId },
			})
		}

		return rootDirectory
	}

	async getServerTree(workspaceId: string) {
		await this.getOrCreateRootDirectory(workspaceId, DirectoryType.SERVER)
		const directories = await this.directoryRepository.find({
			relations: {
				parent: true,
				servers: {},
			},
			where: {
				type: DirectoryType.SERVER,
				workspace: {
					id: workspaceId,
				},
			},
		})

		const tree = this.buildTree(directories)
		return tree
	}

	async create(userId: string, workspaceId: string, data: SaveDirectoryPayload) {
		const result = await this.directoryRepository.createAndSave({
			...data,
			createdBy: { id: userId },
			parent: { id: data.parentId },
			workspace: { id: workspaceId },
		})

		return result
	}

	async delete(directoryId: string, workspaceId: string) {
		const res = await this.directoryRepository.softDelete({
			id: directoryId,
			workspace: { id: workspaceId },
		})

		if (!res.affected) {
			throw new NotFoundException("Directory not found")
		}

		return res
	}
}
