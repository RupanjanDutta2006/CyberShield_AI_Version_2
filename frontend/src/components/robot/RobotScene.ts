import * as THREE from 'three';
import { CyberShieldRobot } from './CyberShieldRobot';

interface SectionCameraKeyframe {
  pos: THREE.Vector3;
  target: THREE.Vector3;
}

const SECTION_CAMERAS: SectionCameraKeyframe[] = [
  // Section 01 — Intro (Full body view on pedestal)
  {
    pos: new THREE.Vector3(0.65, 1.45, 11.8),
    target: new THREE.Vector3(0.65, 1.35, 0),
  },
  // Section 02 — Product (Close zoom on attentive head)
  {
    pos: new THREE.Vector3(0.65, 3.3, 5.8),
    target: new THREE.Vector3(0.65, 3.3, 0),
  },
  // Section 03 — Trust (Intimate portrait framing for quote mode)
  {
    pos: new THREE.Vector3(0.65, 3.3, 5.2),
    target: new THREE.Vector3(0.65, 3.3, 0),
  },
];

export class RobotSceneEngine {
  private container: HTMLElement;
  private scene: THREE.Scene;
  private camera: THREE.PerspectiveCamera;
  private renderer: THREE.WebGLRenderer;
  private isDestroyed: boolean = false;
  private animId: number = 0;

  public robot: CyberShieldRobot;

  // Camera Target States
  private targetCamPos = new THREE.Vector3();
  private targetCamLookAt = new THREE.Vector3();
  private currentCamLookAt = new THREE.Vector3();

  // Pointer Gaze State
  private targetGaze = new THREE.Vector2(0, 0);
  private currentGaze = new THREE.Vector2(0, 0);

  constructor(container: HTMLElement) {
    this.container = container;
    const width = container.clientWidth || window.innerWidth;
    const height = container.clientHeight || window.innerHeight;

    // 1. Scene
    this.scene = new THREE.Scene();

    // 2. Perspective Camera (30° FOV as requested)
    this.camera = new THREE.PerspectiveCamera(30, width / height, 0.1, 100);
    this.camera.position.copy(SECTION_CAMERAS[0].pos);
    this.targetCamPos.copy(SECTION_CAMERAS[0].pos);
    this.targetCamLookAt.copy(SECTION_CAMERAS[0].target);
    this.currentCamLookAt.copy(SECTION_CAMERAS[0].target);

    // 3. Transparent WebGL Renderer
    this.renderer = new THREE.WebGLRenderer({
      powerPreference: 'high-performance',
      antialias: true,
      alpha: true, // Transparent so the warm paper-white #efece6 background shows through
    });
    this.renderer.setSize(width, height);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
    this.renderer.toneMappingExposure = 1.05;
    container.appendChild(this.renderer.domElement);

    // 4. Lighting Rig (Warm studio aesthetic)
    this.setupLighting();

    // 5. Mount Robot
    this.robot = new CyberShieldRobot();
    this.scene.add(this.robot.rootGroup);

    // 6. Listeners
    window.addEventListener('resize', this.onResize);
    window.addEventListener('mousemove', this.onMouseMove);
    window.addEventListener('touchmove', this.onTouchMove, { passive: true });

    // 7. Loop
    this.animate();
  }

  private setupLighting() {
    // Warm Hemisphere Light (Sky: white, Ground: warm paper tone)
    const hemi = new THREE.HemisphereLight('#ffffff', '#efece6', 1.8);
    this.scene.add(hemi);

    // Directional Key Light (Soft warm sunlight from top-right)
    const keyLight = new THREE.DirectionalLight('#fff5eb', 2.2);
    keyLight.position.set(5, 8, 7);
    this.scene.add(keyLight);

    // Rear Rim Light (Cool subtle edge highlight)
    const rimLight = new THREE.DirectionalLight('#e0f0ff', 1.6);
    rimLight.position.set(-6, 6, -5);
    this.scene.add(rimLight);

    // Front Warm Point Light (Fill for chest & face screen)
    const fillLight = new THREE.PointLight('#ffe4d6', 1.2, 16);
    fillLight.position.set(0.65, 3.5, 4.0);
    this.scene.add(fillLight);
  }

  private onResize = () => {
    if (!this.container || this.isDestroyed) return;
    const width = this.container.clientWidth || window.innerWidth;
    const height = this.container.clientHeight || window.innerHeight;
    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(width, height);
  };

  private handlePointer(clientX: number, clientY: number) {
    const normX = (clientX / window.innerWidth) * 2 - 1;
    const normY = -(clientY / window.innerHeight) * 2 + 1;
    this.targetGaze.set(normX, normY);
    this.robot.setPointer(normX, normY);
  }

  private onMouseMove = (e: MouseEvent) => {
    this.handlePointer(e.clientX, e.clientY);
  };

  private onTouchMove = (e: TouchEvent) => {
    if (e.touches.length > 0) {
      this.handlePointer(e.touches[0].clientX, e.touches[0].clientY);
    }
  };

  /**
   * Update camera interpolation based on scroll progress (0.0 to 2.0 continuous float)
   */
  public setScrollProgress(progress: number) {
    const clamped = THREE.MathUtils.clamp(progress, 0, 2);
    const floorIdx = Math.floor(clamped);
    const ceilIdx = Math.min(2, floorIdx + 1);
    const alpha = clamped - floorIdx;

    // Cubic ease-in-out for smooth camera interpolation
    const easeAlpha = alpha < 0.5 ? 4 * alpha * alpha * alpha : 1 - Math.pow(-2 * alpha + 2, 3) / 2;

    const k1 = SECTION_CAMERAS[floorIdx];
    const k2 = SECTION_CAMERAS[ceilIdx] || k1;

    this.targetCamPos.lerpVectors(k1.pos, k2.pos, easeAlpha);
    this.targetCamLookAt.lerpVectors(k1.target, k2.target, easeAlpha);

    this.robot.setSection(Math.round(clamped));
  }

  private animate = () => {
    if (this.isDestroyed) return;

    this.animId = requestAnimationFrame(this.animate);
    const time = performance.now() * 0.001;

    // 1. Smooth Camera Interpolation
    this.currentGaze.lerp(this.targetGaze, 0.05);
    const parallaxX = this.currentGaze.x * 0.35;
    const parallaxY = this.currentGaze.y * 0.22;

    this.camera.position.set(
      this.targetCamPos.x + parallaxX,
      this.targetCamPos.y + parallaxY,
      this.targetCamPos.z
    );

    this.currentCamLookAt.lerp(this.targetCamLookAt, 0.06);
    this.camera.lookAt(this.currentCamLookAt);

    // 2. Update Robot Animation
    this.robot.update(time);

    // 3. Render
    this.renderer.render(this.scene, this.camera);
  };

  public dispose() {
    this.isDestroyed = true;
    cancelAnimationFrame(this.animId);
    window.removeEventListener('resize', this.onResize);
    window.removeEventListener('mousemove', this.onMouseMove);
    window.removeEventListener('touchmove', this.onTouchMove);

    this.robot.dispose();
    this.renderer.dispose();

    if (this.container && this.renderer.domElement) {
      this.container.removeChild(this.renderer.domElement);
    }
  }
}
