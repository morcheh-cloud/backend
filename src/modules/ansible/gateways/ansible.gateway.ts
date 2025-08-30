import { WebSocketGateway } from "@nestjs/websockets";

@WebSocketGateway({
  cors: {
    origin: "*",
  },
})
export class EventsGateway {
  // @WebSocketServer()
  // server: Server;
  // @SubscribeMessage("events")
  // findAll(@MessageBody() data: any): Observable<WsResponse<number>> {
  //   return from([1, 2, 3]).pipe(
  //     map((item) => ({ data: item, event: "events" }))
  //   );
  // }
  // @SubscribeMessage("identity")
  // async identity(@MessageBody() data: number): Promise<number> {
  //   return data;
  // }
}
