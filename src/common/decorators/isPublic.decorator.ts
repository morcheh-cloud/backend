import { SetMetadata } from "@nestjs/common"

export const IS_PUBLIC_KEY = "isPublic"
export const IsPublicApi = () => {
	return SetMetadata(IS_PUBLIC_KEY, true)
}
