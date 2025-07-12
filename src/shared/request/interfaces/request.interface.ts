export interface IAuthUser {
	userId: string
	roleId: number
}

export interface IRequest {
	user: IAuthUser
}
