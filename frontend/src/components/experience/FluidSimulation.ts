import * as THREE from 'three';

/**
 * 2D GPU Navier-Stokes Fluid Solver
 * Manages advection, cursor splatting, curl vorticity confinement,
 * divergence calculation, pressure Poisson iterations, and gradient subtraction.
 */
export class FluidSimulation {
  private renderer: THREE.WebGLRenderer;
  private width: number;
  private height: number;

  // Render Targets (Ping-Pong)
  public velocity: { read: THREE.WebGLRenderTarget; write: THREE.WebGLRenderTarget };
  public density: { read: THREE.WebGLRenderTarget; write: THREE.WebGLRenderTarget };
  public divergence: THREE.WebGLRenderTarget;
  public curl: THREE.WebGLRenderTarget;
  public pressure: { read: THREE.WebGLRenderTarget; write: THREE.WebGLRenderTarget };

  // Shaders & Meshes
  private quadScene: THREE.Scene;
  private quadCamera: THREE.Camera;
  private quadMesh: THREE.Mesh;

  // Shader Materials
  private advectionMat: THREE.ShaderMaterial;
  private splatMat: THREE.ShaderMaterial;
  private curlMat: THREE.ShaderMaterial;
  private vorticityMat: THREE.ShaderMaterial;
  private divergenceMat: THREE.ShaderMaterial;
  private pressureMat: THREE.ShaderMaterial;
  private gradientSubtractMat: THREE.ShaderMaterial;

  // Simulation Parameters
  public velocityDissipation: number = 0.98;
  public densityDissipation: number = 0.97;
  public pressureDissipation: number = 0.95;
  public curlStrength: number = 30.0;
  public pressureIterations: number = 5;

  constructor(renderer: THREE.WebGLRenderer, simRes: number = 256, densityRes: number = 512) {
    this.renderer = renderer;
    this.width = simRes;
    this.height = simRes;

    // Detect float / half-float render target support
    const type = THREE.HalfFloatType;

    const createTarget = (w: number, h: number) =>
      new THREE.WebGLRenderTarget(w, h, {
        type,
        format: THREE.RGBAFormat,
        minFilter: THREE.LinearFilter,
        magFilter: THREE.LinearFilter,
        depthBuffer: false,
        stencilBuffer: false,
      });

    this.velocity = {
      read: createTarget(simRes, simRes),
      write: createTarget(simRes, simRes),
    };
    this.density = {
      read: createTarget(densityRes, densityRes),
      write: createTarget(densityRes, densityRes),
    };
    this.divergence = createTarget(simRes, simRes);
    this.curl = createTarget(simRes, simRes);
    this.pressure = {
      read: createTarget(simRes, simRes),
      write: createTarget(simRes, simRes),
    };

    // Fullscreen quad for FBO rendering
    this.quadScene = new THREE.Scene();
    this.quadCamera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1);
    this.quadMesh = new THREE.Mesh(new THREE.PlaneGeometry(2, 2));
    this.quadScene.add(this.quadMesh);

    // Initialize Shader Materials
    const baseVertex = `
      varying vec2 vUv;
      void main() {
        vUv = uv;
        gl_Position = vec4(position.xy, 0.0, 1.0);
      }
    `;

    // 1. Advection Shader
    this.advectionMat = new THREE.ShaderMaterial({
      vertexShader: baseVertex,
      fragmentShader: `
        uniform sampler2D uVelocity;
        uniform sampler2D uSource;
        uniform vec2 uTexelSize;
        uniform float uDt;
        uniform float uDissipation;
        varying vec2 vUv;
        void main() {
          vec2 coord = vUv - uDt * texture2D(uVelocity, vUv).xy * uTexelSize;
          gl_FragColor = uDissipation * texture2D(uSource, coord);
        }
      `,
      uniforms: {
        uVelocity: { value: null },
        uSource: { value: null },
        uTexelSize: { value: new THREE.Vector2(1 / simRes, 1 / simRes) },
        uDt: { value: 1 / 60 },
        uDissipation: { value: this.velocityDissipation },
      },
    });

    // 2. Splat Shader (Cursor Force & Density Impulse)
    this.splatMat = new THREE.ShaderMaterial({
      vertexShader: baseVertex,
      fragmentShader: `
        uniform sampler2D uTarget;
        uniform float uAspectRatio;
        uniform vec2 uPoint;
        uniform vec3 uColor;
        uniform float uRadius;
        varying vec2 vUv;
        void main() {
          vec2 p = vUv - uPoint;
          p.x *= uAspectRatio;
          vec3 splat = exp(-dot(p, p) / uRadius) * uColor;
          vec3 base = texture2D(uTarget, vUv).xyz;
          gl_FragColor = vec4(base + splat, 1.0);
        }
      `,
      uniforms: {
        uTarget: { value: null },
        uAspectRatio: { value: 1.0 },
        uPoint: { value: new THREE.Vector2() },
        uColor: { value: new THREE.Vector3() },
        uRadius: { value: 0.0035 },
      },
    });

    // 3. Curl Shader
    this.curlMat = new THREE.ShaderMaterial({
      vertexShader: baseVertex,
      fragmentShader: `
        uniform sampler2D uVelocity;
        uniform vec2 uTexelSize;
        varying vec2 vUv;
        void main() {
          float L = texture2D(uVelocity, vUv - vec2(uTexelSize.x, 0.0)).y;
          float R = texture2D(uVelocity, vUv + vec2(uTexelSize.x, 0.0)).y;
          float B = texture2D(uVelocity, vUv - vec2(0.0, uTexelSize.y)).x;
          float T = texture2D(uVelocity, vUv + vec2(0.0, uTexelSize.y)).x;
          float vorticity = R - L - (T - B);
          gl_FragColor = vec4(0.5 * vorticity, 0.0, 0.0, 1.0);
        }
      `,
      uniforms: {
        uVelocity: { value: null },
        uTexelSize: { value: new THREE.Vector2(1 / simRes, 1 / simRes) },
      },
    });

    // 4. Vorticity Confinement Shader
    this.vorticityMat = new THREE.ShaderMaterial({
      vertexShader: baseVertex,
      fragmentShader: `
        uniform sampler2D uVelocity;
        uniform sampler2D uCurl;
        uniform vec2 uTexelSize;
        uniform float uCurlStrength;
        uniform float uDt;
        varying vec2 vUv;
        void main() {
          float L = texture2D(uCurl, vUv - vec2(uTexelSize.x, 0.0)).x;
          float R = texture2D(uCurl, vUv + vec2(uTexelSize.x, 0.0)).x;
          float B = texture2D(uCurl, vUv - vec2(0.0, uTexelSize.y)).x;
          float T = texture2D(uCurl, vUv + vec2(0.0, uTexelSize.y)).x;
          float C = texture2D(uCurl, vUv).x;

          vec2 force = 0.5 * vec2(abs(T) - abs(B), abs(R) - abs(L));
          force /= length(force) + 0.0001;
          force *= uCurlStrength * C * vec2(1.0, -1.0);

          vec2 vel = texture2D(uVelocity, vUv).xy;
          gl_FragColor = vec4(vel + force * uDt, 0.0, 1.0);
        }
      `,
      uniforms: {
        uVelocity: { value: null },
        uCurl: { value: null },
        uTexelSize: { value: new THREE.Vector2(1 / simRes, 1 / simRes) },
        uCurlStrength: { value: this.curlStrength },
        uDt: { value: 1 / 60 },
      },
    });

    // 5. Divergence Shader
    this.divergenceMat = new THREE.ShaderMaterial({
      vertexShader: baseVertex,
      fragmentShader: `
        uniform sampler2D uVelocity;
        uniform vec2 uTexelSize;
        varying vec2 vUv;
        void main() {
          float L = texture2D(uVelocity, vUv - vec2(uTexelSize.x, 0.0)).x;
          float R = texture2D(uVelocity, vUv + vec2(uTexelSize.x, 0.0)).x;
          float B = texture2D(uVelocity, vUv - vec2(0.0, uTexelSize.y)).y;
          float T = texture2D(uVelocity, vUv + vec2(0.0, uTexelSize.y)).y;
          float div = 0.5 * (R - L + T - B);
          gl_FragColor = vec4(div, 0.0, 0.0, 1.0);
        }
      `,
      uniforms: {
        uVelocity: { value: null },
        uTexelSize: { value: new THREE.Vector2(1 / simRes, 1 / simRes) },
      },
    });

    // 6. Jacobi Pressure Solver Shader
    this.pressureMat = new THREE.ShaderMaterial({
      vertexShader: baseVertex,
      fragmentShader: `
        uniform sampler2D uPressure;
        uniform sampler2D uDivergence;
        uniform vec2 uTexelSize;
        varying vec2 vUv;
        void main() {
          float L = texture2D(uPressure, vUv - vec2(uTexelSize.x, 0.0)).x;
          float R = texture2D(uPressure, vUv + vec2(uTexelSize.x, 0.0)).x;
          float B = texture2D(uPressure, vUv - vec2(0.0, uTexelSize.y)).x;
          float T = texture2D(uPressure, vUv + vec2(0.0, uTexelSize.y)).x;
          float div = texture2D(uDivergence, vUv).x;
          float p = (L + R + B + T - div) * 0.25;
          gl_FragColor = vec4(p, 0.0, 0.0, 1.0);
        }
      `,
      uniforms: {
        uPressure: { value: null },
        uDivergence: { value: null },
        uTexelSize: { value: new THREE.Vector2(1 / simRes, 1 / simRes) },
      },
    });

    // 7. Gradient Subtraction Shader (Projection)
    this.gradientSubtractMat = new THREE.ShaderMaterial({
      vertexShader: baseVertex,
      fragmentShader: `
        uniform sampler2D uPressure;
        uniform sampler2D uVelocity;
        uniform vec2 uTexelSize;
        varying vec2 vUv;
        void main() {
          float L = texture2D(uPressure, vUv - vec2(uTexelSize.x, 0.0)).x;
          float R = texture2D(uPressure, vUv + vec2(uTexelSize.x, 0.0)).x;
          float B = texture2D(uPressure, vUv - vec2(0.0, uTexelSize.y)).x;
          float T = texture2D(uPressure, vUv + vec2(0.0, uTexelSize.y)).x;
          vec2 vel = texture2D(uVelocity, vUv).xy;
          vel.xy -= 0.5 * vec2(R - L, T - B);
          gl_FragColor = vec4(vel, 0.0, 1.0);
        }
      `,
      uniforms: {
        uPressure: { value: null },
        uVelocity: { value: null },
        uTexelSize: { value: new THREE.Vector2(1 / simRes, 1 / simRes) },
      },
    });
  }

  private renderPass(mat: THREE.ShaderMaterial, target: THREE.WebGLRenderTarget | null) {
    this.quadMesh.material = mat;
    this.renderer.setRenderTarget(target);
    this.renderer.render(this.quadScene, this.quadCamera);
    this.renderer.setRenderTarget(null);
  }

  /**
   * Apply an external pointer force / splat to velocity and density
   */
  public splat(x: number, y: number, dx: number, dy: number, color?: THREE.Color) {
    const aspect = this.width / this.height;

    // Splat velocity
    this.splatMat.uniforms.uTarget.value = this.velocity.read.texture;
    this.splatMat.uniforms.uAspectRatio.value = aspect;
    this.splatMat.uniforms.uPoint.value.set(x, y);
    this.splatMat.uniforms.uColor.value.set(dx * 45.0, dy * 45.0, 0.0);
    this.splatMat.uniforms.uRadius.value = 0.0035;
    this.renderPass(this.splatMat, this.velocity.write);

    // Swap velocity
    const tempV = this.velocity.read;
    this.velocity.read = this.velocity.write;
    this.velocity.write = tempV;

    // Splat density
    const splatColor = color || new THREE.Color(0.67, 0.53, 1.0); // #AA88FF lavender
    this.splatMat.uniforms.uTarget.value = this.density.read.texture;
    this.splatMat.uniforms.uColor.value.set(splatColor.r * 1.5, splatColor.g * 1.5, splatColor.b * 1.5);
    this.splatMat.uniforms.uRadius.value = 0.005;
    this.renderPass(this.splatMat, this.density.write);

    // Swap density
    const tempD = this.density.read;
    this.density.read = this.density.write;
    this.density.write = tempD;
  }

  /**
   * Step the fluid simulation forward in time
   */
  public step(dt: number = 1 / 60) {
    // 1. Curl Pass
    this.curlMat.uniforms.uVelocity.value = this.velocity.read.texture;
    this.renderPass(this.curlMat, this.curl);

    // 2. Vorticity Confinement
    this.vorticityMat.uniforms.uVelocity.value = this.velocity.read.texture;
    this.vorticityMat.uniforms.uCurl.value = this.curl.texture;
    this.vorticityMat.uniforms.uDt.value = dt;
    this.renderPass(this.vorticityMat, this.velocity.write);
    let temp = this.velocity.read;
    this.velocity.read = this.velocity.write;
    this.velocity.write = temp;

    // 3. Advection: Velocity
    this.advectionMat.uniforms.uVelocity.value = this.velocity.read.texture;
    this.advectionMat.uniforms.uSource.value = this.velocity.read.texture;
    this.advectionMat.uniforms.uDt.value = dt;
    this.advectionMat.uniforms.uDissipation.value = this.velocityDissipation;
    this.renderPass(this.advectionMat, this.velocity.write);
    temp = this.velocity.read;
    this.velocity.read = this.velocity.write;
    this.velocity.write = temp;

    // 4. Advection: Density
    this.advectionMat.uniforms.uVelocity.value = this.velocity.read.texture;
    this.advectionMat.uniforms.uSource.value = this.density.read.texture;
    this.advectionMat.uniforms.uDissipation.value = this.densityDissipation;
    this.renderPass(this.advectionMat, this.density.write);
    temp = this.density.read;
    this.density.read = this.density.write;
    this.density.write = temp;

    // 5. Divergence
    this.divergenceMat.uniforms.uVelocity.value = this.velocity.read.texture;
    this.renderPass(this.divergenceMat, this.divergence);

    // 6. Pressure Solve (Jacobi iterations)
    this.pressureMat.uniforms.uDivergence.value = this.divergence.texture;
    for (let i = 0; i < this.pressureIterations; i++) {
      this.pressureMat.uniforms.uPressure.value = this.pressure.read.texture;
      this.renderPass(this.pressureMat, this.pressure.write);
      temp = this.pressure.read;
      this.pressure.read = this.pressure.write;
      this.pressure.write = temp;
    }

    // 7. Gradient Subtraction (Projection)
    this.gradientSubtractMat.uniforms.uPressure.value = this.pressure.read.texture;
    this.gradientSubtractMat.uniforms.uVelocity.value = this.velocity.read.texture;
    this.renderPass(this.gradientSubtractMat, this.velocity.write);
    temp = this.velocity.read;
    this.velocity.read = this.velocity.write;
    this.velocity.write = temp;
  }

  public getVelocityTexture(): THREE.Texture {
    return this.velocity.read.texture;
  }

  public getDensityTexture(): THREE.Texture {
    return this.density.read.texture;
  }

  public dispose() {
    this.velocity.read.dispose();
    this.velocity.write.dispose();
    this.density.read.dispose();
    this.density.write.dispose();
    this.divergence.dispose();
    this.curl.dispose();
    this.pressure.read.dispose();
    this.pressure.write.dispose();
  }
}
