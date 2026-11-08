import * as THREE from 'three';
import { FluidSimulation } from './FluidSimulation';
import { ParticleSimulation } from './ParticleSimulation';

/**
 * Master WebGL Scene Orchestrator
 * Integrates PerspectiveCamera (30° FOV), Fluid Simulation, GPGPU Particle Simulation,
 * and mouse/touch gaze tracking.
 */
export class ParticleSceneEngine {
  private container: HTMLElement;
  private scene: THREE.Scene;
  private camera: THREE.PerspectiveCamera;
  private renderer: THREE.WebGLRenderer;
  private isDestroyed: boolean = false;
  private animId: number = 0;

  // Subsystems
  public fluid: FluidSimulation;
  public particles: ParticleSimulation;

  // Interaction State
  private prevMouse = new THREE.Vector2(-1, -1);
  private targetGaze = new THREE.Vector2(0, 0);
  private currentGaze = new THREE.Vector2(0, 0);
  private startTime: number = performance.now();

  constructor(container: HTMLElement) {
    this.container = container;
    const width = container.clientWidth || window.innerWidth;
    const height = container.clientHeight || window.innerHeight;

    // 1. Scene
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color('#000000');

    // 2. Perspective Camera (30° FOV as specified in brief)
    this.camera = new THREE.PerspectiveCamera(30, width / height, 0.1, 100);
    this.camera.position.set(0, 0, 16.5);

    // 3. Renderer
    this.renderer = new THREE.WebGLRenderer({
      powerPreference: 'high-performance',
      antialias: true,
      alpha: false,
    });
    this.renderer.setSize(width, height);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(this.renderer.domElement);

    // 4. Detect mobile
    const isMobile = window.innerWidth < 768;

    // 5. Initialize Fluid & Particle Simulations
    this.fluid = new FluidSimulation(this.renderer, isMobile ? 128 : 256, isMobile ? 256 : 512);
    this.particles = new ParticleSimulation(this.renderer, isMobile);
    this.scene.add(this.particles.pointsMesh);

    // 6. Event Listeners
    window.addEventListener('resize', this.onResize);
    window.addEventListener('mousemove', this.onMouseMove);
    window.addEventListener('touchmove', this.onTouchMove, { passive: true });
    window.addEventListener('touchstart', this.onTouchStart, { passive: true });

    // 7. Start RAF
    this.animate();
  }

  private onResize = () => {
    if (!this.container || this.isDestroyed) return;
    const width = this.container.clientWidth || window.innerWidth;
    const height = this.container.clientHeight || window.innerHeight;
    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(width, height);
  };

  private handlePointerMove(clientX: number, clientY: number) {
    const normX = clientX / window.innerWidth;
    const normY = 1.0 - (clientY / window.innerHeight);

    if (this.prevMouse.x > 0 && this.prevMouse.y > 0) {
      const dx = normX - this.prevMouse.x;
      const dy = normY - this.prevMouse.y;
      const speed = Math.sqrt(dx * dx + dy * dy);

      if (speed > 0.0005) {
        // Splat into fluid simulation
        this.fluid.splat(normX, normY, dx, dy);
      }
    }

    this.prevMouse.set(normX, normY);

    // Gaze parallax target (-1 to 1)
    const gazeX = (clientX / window.innerWidth) * 2 - 1;
    const gazeY = -(clientY / window.innerHeight) * 2 + 1;
    this.targetGaze.set(gazeX, gazeY);
  }

  private onMouseMove = (e: MouseEvent) => {
    this.handlePointerMove(e.clientX, e.clientY);
  };

  private onTouchMove = (e: TouchEvent) => {
    if (e.touches.length > 0) {
      this.handlePointerMove(e.touches[0].clientX, e.touches[0].clientY);
    }
  };

  private onTouchStart = (e: TouchEvent) => {
    if (e.touches.length > 0) {
      this.prevMouse.set(
        e.touches[0].clientX / window.innerWidth,
        1.0 - (e.touches[0].clientY / window.innerHeight)
      );
    }
  };

  private animate = () => {
    if (this.isDestroyed) return;

    this.animId = requestAnimationFrame(this.animate);
    const now = performance.now();
    const time = (now - this.startTime) * 0.001;

    // 1. Step Navier-Stokes 2D Fluid Grid
    this.fluid.step(1 / 60);

    // 2. Step 3D GPU Particle Ping-Pong Simulation
    this.particles.step(this.fluid, time, 1 / 60);

    // 3. Smooth Camera Gaze Interpolation
    this.currentGaze.lerp(this.targetGaze, 0.045);
    const gazeOffsetX = this.currentGaze.x * 0.6;
    const gazeOffsetY = this.currentGaze.y * 0.4;
    this.camera.position.x = gazeOffsetX;
    this.camera.position.y = gazeOffsetY;
    this.camera.lookAt(0.8, 0, 0); // Keep lookAt aligned slightly right of center

    // 4. Render Scene
    this.renderer.render(this.scene, this.camera);
  };

  public dispose() {
    this.isDestroyed = true;
    cancelAnimationFrame(this.animId);
    window.removeEventListener('resize', this.onResize);
    window.removeEventListener('mousemove', this.onMouseMove);
    window.removeEventListener('touchmove', this.onTouchMove);
    window.removeEventListener('touchstart', this.onTouchStart);

    this.fluid.dispose();
    this.particles.dispose();
    this.renderer.dispose();

    if (this.container && this.renderer.domElement) {
      this.container.removeChild(this.renderer.domElement);
    }
  }
}
