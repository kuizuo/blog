export type WorkerRemoteMessage = {
  type: 'ready'
}

export type WorkerMessage =
  | {
    type: 'attach'
    canvas: OffscreenCanvas
  }
  | {
    type: 'detach'
  }
  | {
    type: 'resize'
    width: number
    height: number
  }
