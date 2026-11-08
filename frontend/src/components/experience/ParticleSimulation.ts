import * as THREE from 'three';
import { FluidSimulation } from './FluidSimulation';

/**
 * GPU Particle Simulation Engine
 * Manages 262,144 (desktop) / 16,384 (mobile) particles using ping-pong GPGPU render targets.
 * Couples with 2D Navier-Stokes fluid velocity field and restores back to the sculpted 3D digital shield vortex.
 */
export class ParticleSimulation {
  private renderer: THREE.WebGLRenderer;
  public particleCount: number;
  public textureSize: number;

  // Render Targets (Ping-Pong FBOs)
  public posTargetA: THREE.WebGLRenderTarget;
  public posTargetB: THREE.WebGLRenderTarget;
  public velTargetA: THREE.WebGLRenderTarget;
  public velTargetB: THREE.WebGLRenderTarget;
  public originTexture: THREE.DataTexture;

  // Simulation Quad
  private simScene: THREE.Scene;
  private simCamera: THREE.Camera;
  private simQuad: THREE.Mesh;
  private simMaterial: THREE.ShaderMaterial;

  // Particle Points Mesh
  public pointsMesh: THREE.Points;
  private renderMaterial: THREE.ShaderMaterial;

  constructor(renderer: THREE.WebGLRenderer, isMobile: boolean = false) {
    this.renderer = renderer;
    this.textureSize = isMobile ? 128 : 512;
    this.particleCount = this.textureSize * this.textureSize;

    const size = this.textureSize;
    const type = THREE.HalfFloatType;

    const createTarget = () =>
      new THREE.WebGLRenderTarget(size, size, {
        type,
        format: THREE.RGBAFormat,
        minFilter: THREE.NearestFilter,
        magFilter: THREE.NearestFilter,
        depthBuffer: false,
        stencilBuffer: false,
      });

    this.posTargetA = createTarget();
    this.posTargetB = createTarget();
    this.velTargetA = createTarget();
    this.velTargetB = createTarget();

    // 1. Generate Canonical 3D Sculpted Digital Shield Coordinates
    const { positions, variations } = this.generateShieldShape(size);

    this.originTexture = new THREE.DataTexture(
      positions,
      size,
      size,
      THREE.RGBAFormat,
      THREE.FloatType
    );
    this.originTexture.needsUpdate = true;

    // Initialize posTargetA with initial positions
    const initMat = new THREE.ShaderMaterial({
      vertexShader: `
        varying vec2 vUv;
        void main() { vUv = uv; gl_Position = vec4(position.xy, 0.0, 1.0); }
      `,
      fragmentShader: `
        uniform sampler2D uTex;
        varying vec2 vUv;
        void main() { gl_FragColor = texture2D(uTex, vUv); }
      `,
      uniforms: { uTex: { value: this.originTexture } },
    });
    this.simScene = new THREE.Scene();
    this.simCamera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1);
    this.simQuad = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), initMat);
    this.simScene.add(this.simQuad);

    this.renderer.setRenderTarget(this.posTargetA);
    this.renderer.render(this.simScene, this.simCamera);
    this.renderer.setRenderTarget(this.posTargetB);
    this.renderer.render(this.simScene, this.simCamera);
    this.renderer.setRenderTarget(null);

    // 2. GPGPU Simulation Shader
    this.simMaterial = new THREE.ShaderMaterial({
      vertexShader: `
        varying vec2 vUv;
        void main() { vUv = uv; gl_Position = vec4(position.xy, 0.0, 1.0); }
      `,
      fragmentShader: `
        uniform sampler2D uCurrentPos;
        uniform sampler2D uCurrentVel;
        uniform sampler2D uOriginPos;
        uniform sampler2D uFluidVelocity;
        uniform vec2 uResolution;
        uniform float uTime;
        uniform float uDt;
        uniform float uSpringK;
        uniform float uDamping;
        varying vec2 vUv;

        // 3D Simplex Curl Noise approximation
        vec3 hash3(vec3 p) {
          p = vec3(dot(p, vec3(127.1, 311.7, 74.7)),
                   dot(p, vec3(269.5, 183.3, 246.1)),
                   dot(p, vec3(113.5, 271.9, 124.6)));
          return -1.0 + 2.0 * fract(sin(p) * 43758.5453123);
        }

        vec3 curlNoise(vec3 p) {
          const float e = 0.08;
          vec3 dx = vec3(e, 0.0, 0.0);
          vec3 dy = vec3(0.0, e, 0.0);
          vec3 dz = vec3(0.0, 0.0, e);

          vec3 p_x0 = hash3(p - dx);
          vec3 p_x1 = hash3(p + dx);
          vec3 p_y0 = hash3(p - dy);
          vec3 p_y1 = hash3(p + dy);
          vec3 p_z0 = hash3(p - dz);
          vec3 p_z1 = hash3(p + dz);

          float x = p_y1.z - p_y0.z - p_z1.y + p_z0.y;
          float y = p_z1.x - p_z0.x - p_x1.z + p_x0.z;
          float z = p_x1.y - p_x0.y - p_y1.x + p_y0.x;

          return normalize(vec3(x, y, z) / (2.0 * e));
        }

        void main() {
          vec4 posData = texture2D(uCurrentPos, vUv);
          vec4 velData = texture2D(uCurrentVel, vUv);
          vec4 originData = texture2D(uOriginPos, vUv);

          vec3 pos = posData.xyz;
          vec3 vel = velData.xyz;
          vec3 origin = originData.xyz;

          // 1. Spring restoration force toward anchor
          vec3 toOrigin = origin - pos;
          float dist = length(toOrigin);
          vec3 fSpring = toOrigin * uSpringK;

          // 2. Micro Curl noise field for organic living movement
          vec3 fCurl = curlNoise(pos * 0.45 + vec3(uTime * 0.12)) * 0.35;

          // 3. Fluid momentum coupling
          // Map 3D pos (-4 to +4) to screen UV (0 to 1)
          vec2 screenUV = clamp((pos.xy / 8.0) + vec2(0.5, 0.5), 0.0, 1.0);
          vec2 fluidV = texture2D(uFluidVelocity, screenUV).xy;
          vec3 fFluid = vec3(fluidV.x, fluidV.y, 0.0) * 1.8;

          // 4. Integrate
          vec3 totalForce = fSpring + fCurl + fFluid;
          vel = vel * uDamping + totalForce * uDt;
          pos += vel * uDt;

          gl_FragColor = vec4(pos, posData.w);
        }
      `,
      uniforms: {
        uCurrentPos: { value: null },
        uCurrentVel: { value: null },
        uOriginPos: { value: this.originTexture },
        uFluidVelocity: { value: null },
        uResolution: { value: new THREE.Vector2(size, size) },
        uTime: { value: 0 },
        uDt: { value: 1 / 60 },
        uSpringK: { value: 3.2 },
        uDamping: { value: 0.94 },
      },
    });

    // 3. Setup Particle Points Mesh for Rendering
    const geo = new THREE.BufferGeometry();
    const refArray = new Float32Array(this.particleCount * 2);
    for (let i = 0; i < size; i++) {
      for (let j = 0; j < size; j++) {
        const idx = (i * size + j) * 2;
        refArray[idx] = (j + 0.5) / size;
        refArray[idx + 1] = (i + 0.5) / size;
      }
    }
    geo.setAttribute('reference', new THREE.BufferAttribute(refArray, 2));
    geo.setAttribute('variation', new THREE.BufferAttribute(variations, 1));

    this.renderMaterial = new THREE.ShaderMaterial({
      vertexShader: `
        uniform sampler2D uPosTexture;
        uniform float uBaseSize;
        attribute vec2 reference;
        attribute float variation;
        varying float vVariation;
        varying vec3 vViewPos;

        void main() {
          vec4 posData = texture2D(uPosTexture, reference);
          vVariation = variation;

          vec4 mvPosition = modelViewMatrix * vec4(posData.xyz, 1.0);
          vViewPos = mvPosition.xyz;

          // Size attenuation with perspective
          gl_PointSize = uBaseSize * (280.0 / -mvPosition.z);
          gl_PointSize = clamp(gl_PointSize, 1.0, 14.0);

          gl_Position = projectionMatrix * mvPosition;
        }
      `,
      fragmentShader: `
        varying float vVariation;
        varying vec3 vViewPos;

        void main() {
          // Circular particle shape
          vec2 coord = gl_PointCoord - vec2(0.5);
          float r = length(coord);
          if (r > 0.5) discard;

          // Soft radial falloff / matcap sphere lighting
          float alpha = smoothstep(0.5, 0.08, r);

          // Color Palette: Mostly soft white/grey with sparse lavender highlights
          vec3 colWhite = vec3(0.94, 0.94, 0.98);
          vec3 colGrey = vec3(0.54, 0.54, 0.62);
          vec3 colLavender = vec3(0.67, 0.53, 1.0); // #AA88FF

          vec3 finalColor;
          if (vVariation > 0.88) {
            finalColor = colLavender;
            alpha *= 1.35;
          } else if (vVariation > 0.5) {
            finalColor = colWhite;
          } else {
            finalColor = colGrey;
          }

          gl_FragColor = vec4(finalColor, alpha * 0.82);
        }
      `,
      uniforms: {
        uPosTexture: { value: this.posTargetA.texture },
        uBaseSize: { value: isMobile ? 2.5 : 2.0 },
      },
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });

    this.pointsMesh = new THREE.Points(geo, this.renderMaterial);
  }

  /**
   * Mathematically sculpt the 3D Digital Shield Vortex
   */
  private generateShieldShape(size: number) {
    const total = size * size;
    const positions = new Float32Array(total * 4);
    const variations = new Float32Array(total);

    for (let i = 0; i < total; i++) {
      // Coordinate parametrization
      const u = (i / total) * Math.PI * 2 * 12.0;
      const v = (Math.random() - 0.5) * Math.PI * 2;
      const rRing = 0.45 + Math.random() * 0.35;

      // Parametric twisted shield equations
      const baseR = 2.3 + Math.sin(u * 2.0) * 0.4;
      const x = (baseR + rRing * Math.cos(v)) * Math.sin(u) + 1.35; // Shifted right of center
      const y = (3.1 * Math.cos(u) - 0.28 * Math.abs(x - 1.35)) + rRing * Math.sin(v);
      const z = 0.85 * Math.sin(u * 2.0) + 0.45 * Math.cos(v) + (Math.random() - 0.5) * 0.25;

      const idx = i * 4;
      positions[idx] = x;
      positions[idx + 1] = y;
      positions[idx + 2] = z;
      positions[idx + 3] = Math.random(); // Random seed

      // Variation: 0.0 to 1.0 (determines white/grey vs lavender)
      variations[i] = Math.random();
    }

    return { positions, variations };
  }

  /**
   * Step the GPU particle simulation using ping-pong FBOs
   */
  public step(fluid: FluidSimulation, time: number, dt: number = 1 / 60) {
    this.simQuad.material = this.simMaterial;
    this.simMaterial.uniforms.uCurrentPos.value = this.posTargetA.texture;
    this.simMaterial.uniforms.uCurrentVel.value = this.velTargetA.texture;
    this.simMaterial.uniforms.uFluidVelocity.value = fluid.getVelocityTexture();
    this.simMaterial.uniforms.uTime.value = time;
    this.simMaterial.uniforms.uDt.value = dt;

    // Render new position into posTargetB
    this.renderer.setRenderTarget(this.posTargetB);
    this.renderer.render(this.simScene, this.simCamera);
    this.renderer.setRenderTarget(null);

    // Swap position targets
    const tempP = this.posTargetA;
    this.posTargetA = this.posTargetB;
    this.posTargetB = tempP;

    // Update render texture uniform
    this.renderMaterial.uniforms.uPosTexture.value = this.posTargetA.texture;
  }

  public dispose() {
    this.posTargetA.dispose();
    this.posTargetB.dispose();
    this.velTargetA.dispose();
    this.velTargetB.dispose();
    this.originTexture.dispose();
    this.pointsMesh.geometry.dispose();
    this.renderMaterial.dispose();
    this.simMaterial.dispose();
  }
}
