// shaders are loaded at runtime (fetched from static/) and passed into Renderer

const PARTICLE_COUNT = 64000

const SIZEOF_F32 = Float32Array.BYTES_PER_ELEMENT
const SIZEOF_I32 = Uint32Array.BYTES_PER_ELEMENT

export class Renderer {
  // Renderer environment
  private context: GPUCanvasContext
  private device: GPUDevice

  // Render pipeline
  private renderPipeline: GPURenderPipeline
  private renderBindGroup: GPUBindGroup

  // Compute pipeline
  private computePipeline: GPUComputePipeline
  private computeBindGroup: GPUBindGroup

  // Shared resources
  private uniformBuffer: GPUBuffer
  private simulationContextBuffer: GPUBuffer
  private simulationContextLocalBuffer: ArrayBuffer

  // Renderer state
  private started = false
  private lastFrameTime = 0
  private time = 0

  constructor(context: GPUCanvasContext, device: GPUDevice, shadersCode: string) {
    this.context = context
    this.device = device

    const presentationFormat = navigator.gpu.getPreferredCanvasFormat()
    this.context.configure({
      device,
      format: presentationFormat,
      alphaMode: 'premultiplied',
    })

    const module = device.createShaderModule({
      code: shadersCode,
    })

    /*
     * Initialize the render pipeline.
     */
    const renderBindGroupLayout = device.createBindGroupLayout({
      entries: [
        {
          binding: 0,
          visibility: GPUShaderStage.VERTEX | GPUShaderStage.FRAGMENT,
          buffer: {
            type: 'uniform',
          },
        },
        {
          binding: 1,
          visibility: GPUShaderStage.VERTEX,
          buffer: {
            type: 'read-only-storage',
          },
        },
      ],
    })
    const renderPipeline = device.createRenderPipeline({
      layout: device.createPipelineLayout({
        bindGroupLayouts: [renderBindGroupLayout],
      }),
      vertex: {
        module,
        entryPoint: 'particleVertex',
      },
      fragment: {
        module,
        entryPoint: 'particleFragment',
        targets: [
          {
            format: presentationFormat,
            // Use premultiplied blend here.
            blend: {
              color: {
                operation: 'add',
                srcFactor: 'one',
                dstFactor: 'one-minus-src-alpha',
              },
              alpha: {
                operation: 'add',
                srcFactor: 'one',
                dstFactor: 'one-minus-src-alpha',
              },
            },
          },
        ],
      },
      primitive: {
        topology: 'triangle-strip',
      },
    })
    this.renderPipeline = renderPipeline

    /*
     * Initialize the compute pipeline.
     */
    const computeBindGroupLayout = device.createBindGroupLayout({
      entries: [
        {
          binding: 0,
          visibility: GPUShaderStage.COMPUTE,
          buffer: {
            type: 'uniform',
          },
        },
        {
          binding: 1,
          visibility: GPUShaderStage.COMPUTE,
          buffer: {
            type: 'storage',
          },
        },
        {
          binding: 2,
          visibility: GPUShaderStage.COMPUTE,
          buffer: {
            type: 'storage',
          },
        },
      ],
    })
    const computePipeline = device.createComputePipeline({
      layout: device.createPipelineLayout({
        bindGroupLayouts: [computeBindGroupLayout],
      }),
      compute: {
        module,
        entryPoint: 'updateParticles',
      },
    })
    this.computePipeline = computePipeline

    /*
     * Initialize the buffers.
     */
    const uniformBuffer = device.createBuffer({
      size: 2 * SIZEOF_F32, // { viewportSize: vec2f }
      usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
    })
    this.uniformBuffer = uniformBuffer

    const particleObjectBuffer = device.createBuffer({
      // {
      //   position: vec2f,
      //   size: vec2f,
      //   velocity: vec2f,
      //   distance: f32,
      //   opacity: f32,
      //   spawned: i32,
      // }
      size: PARTICLE_COUNT * (3 * 2 * SIZEOF_F32 + 2 * SIZEOF_F32 + SIZEOF_I32),
      usage: GPUBufferUsage.VERTEX | GPUBufferUsage.STORAGE,
    })

    const simulationContextBuffer = device.createBuffer({
      // { time: f32, deltaTime: f32, randSeed: f32, particlesToSpawn: i32 }
      size: 3 * SIZEOF_F32 + SIZEOF_I32,
      usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
    })
    this.simulationContextBuffer = simulationContextBuffer
    this.simulationContextLocalBuffer = new ArrayBuffer(
      simulationContextBuffer.size,
    )

    /*
     * Initialize the bind groups.
     */
    const renderBindGroup = device.createBindGroup({
      layout: renderBindGroupLayout,
      entries: [
        {
          binding: 0,
          resource: {
            buffer: uniformBuffer,
          },
        },
        {
          binding: 1,
          resource: {
            buffer: particleObjectBuffer,
          },
        },
      ],
    })
    this.renderBindGroup = renderBindGroup

    const computeBindGroup = device.createBindGroup({
      layout: computeBindGroupLayout,
      entries: [
        {
          binding: 0,
          resource: {
            buffer: uniformBuffer,
          },
        },
        {
          binding: 1,
          resource: {
            buffer: particleObjectBuffer,
          },
        },
        {
          binding: 2,
          resource: {
            buffer: simulationContextBuffer,
          },
        },
      ],
    })
    this.computeBindGroup = computeBindGroup
  }

  start() {
    if (this.started) {
      return
    }

    // Make sure the renderer is resized before starting.
    this.resize()

    this.started = true
    this.lastFrameTime = performance.now()
    this.time = 0
    this.scheduleFrame()
  }

  stop() {
    this.started = false
  }

  resize() {
    const texture = this.context.getCurrentTexture()
    this.device.queue.writeBuffer(
      this.uniformBuffer,
      0,
      new Float32Array([texture.width, texture.height]),
    )

    if (this.started) {
      this.renderFrame()
    }
  }

  private updateSimulationContext() {
    const now = performance.now()
    const timeDelta = now - this.lastFrameTime
    this.lastFrameTime = now
    this.time += timeDelta

    const bufferView = new DataView(this.simulationContextLocalBuffer)
    // Note: WGSL requires little-endian byte order.
    bufferView.setFloat32(0, this.time, true)
    bufferView.setFloat32(4, timeDelta, true)
    bufferView.setFloat32(8, Math.random(), true)
    bufferView.setInt32(12, Math.random() * timeDelta, true)
  }

  private scheduleFrame() {
    requestAnimationFrame(() => {
      if (!this.started) return

      this.renderFrame()
      this.scheduleFrame()
    })
  }

  private renderFrame() {
    const device = this.device
    const commandQueue = device.queue
    const commandEncoder = device.createCommandEncoder()

    // Update the simulation context.
    this.updateSimulationContext()
    commandQueue.writeBuffer(
      this.simulationContextBuffer,
      0,
      this.simulationContextLocalBuffer,
    )

    // Update the particles.
    const computePassEncoder = commandEncoder.beginComputePass()
    computePassEncoder.setPipeline(this.computePipeline)
    computePassEncoder.setBindGroup(0, this.computeBindGroup)
    computePassEncoder.dispatchWorkgroups(PARTICLE_COUNT / 64)
    computePassEncoder.end()

    // Draw the particles.
    const renderPassDescriptor: GPURenderPassDescriptor = {
      colorAttachments: [
        {
          view: this.context.getCurrentTexture().createView(),
          clearValue: [0, 0, 0, 0],
          loadOp: 'clear',
          storeOp: 'store',
        },
      ],
    }
    const renderPassEncoder
      = commandEncoder.beginRenderPass(renderPassDescriptor)
    renderPassEncoder.setPipeline(this.renderPipeline)
    renderPassEncoder.setBindGroup(0, this.renderBindGroup)
    renderPassEncoder.draw(4, PARTICLE_COUNT, 0, 0)
    renderPassEncoder.end()

    commandQueue.submit([commandEncoder.finish()])
  }
}
