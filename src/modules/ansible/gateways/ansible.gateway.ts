// src/ansible/ansible.gateway.ts
import {
	OnGatewayInit,
	SubscribeMessage,
	WebSocketGateway,
	WebSocketServer,
} from "@nestjs/websockets"
import { Server } from "socket.io"

@WebSocketGateway({
	cors: { origin: "*" },
	namespace: "/ansible",
})
export class AnsibleGateway implements OnGatewayInit {
	@WebSocketServer()
	public server!: Server

	afterInit() {
		console.log("WebSocket server initialized")
	}
	/**
	 * Emit a structured event to a specific job "room".
	 * Clients should join the room by jobId after connecting.
	 */
	emit(jobId: string, event: AnsibleEvent) {
		this.server.to(jobId).emit("ansible:event", event)
	}

	@SubscribeMessage("join")
	handleJoin() {
		// @ConnectedSocket() client: Socket,
		// @MessageBody() data: { room: string }
		console.log("here")
		// client.join(data.room);
	}
}

/** Event shape sent to clients */
export type AnsibleEvent =
	| { type: "play-start"; play: string; time: string }
	| { type: "task-start"; task: string; time: string }
	| {
			type: "host-result"
			host: string
			status: "ok" | "changed" | "failed" | "skipped" | "unreachable"
			summary?: string
			time: string
	  }
	| { type: "stdout"; line: string; time: string }
	| { type: "stderr"; line: string; time: string }
	| { type: "exit"; code: number; signal: NodeJS.Signals | null; time: string }
