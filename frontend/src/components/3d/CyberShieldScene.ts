import * as THREE from 'three';
import { interpolateKeyframe } from './CameraChoreographer';
import { cyberAudio } from '../audio/CyberShieldAudio';

export class CyberShieldSceneEngine {
  private container: HTMLElement;
  private scene: THREE.Scene;
  private camera: THREE.PerspectiveCamera;
  private renderer: THREE.WebGLRenderer;
  private isDestroyed: boolean = false;
  private reqId: number = 0;

  // Scene Objects
  private shieldGroup: THREE.Group;
  private shieldOuterMesh!: THREE.Mesh;
  private shieldCoreMesh!: THREE.Mesh;
  private monoliths: { mesh: THREE.Mesh; baseAngle: number; speed: number; yOffset: number; rotSpeed: THREE.Vector3 }[] = [];
  private laserGroup: THREE.Group;
  private laserHMesh!: THREE.Mesh;
  private laserVMesh!: THREE.Mesh;
  private laserHalo!: THREE.Mesh;
  private laserPointLight!: THREE.PointLight;
  private particleSystem!: THREE.Points;

  // Animation State
  private targetProgress: number = 0;
  private currentProgress: number = 0;
  private targetMouse = new THREE.Vector2(0, 0);
  private currentMouse = new THREE.Vector2(0, 0);
  private lastScrollTime: number = Date.now();
  private lastChapterReported: number = 0;

  constructor(container: HTMLElement) {
    this.container = container;

    // 1. Scene & Fog
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color('#030305');
    this.scene.fog = new THREE.FogExp2('#020204', 0.038);

    // 2. Camera
    const width = container.clientWidth || window.innerWidth;
    const height = container.clientHeight || window.innerHeight;
    this.camera = new THREE.PerspectiveCamera(48, width / height, 0.1, 100);
    this.camera.position.set(0, 1.2, 13.5);

    // 3. Renderer
    this.renderer = new THREE.WebGLRenderer({
      powerPreference: 'high-performance',
      antialias: true,
      alpha: false,
    });
    this.renderer.setSize(width, height);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
    this.renderer.toneMappingExposure = 1.35;
    container.appendChild(this.renderer.domElement);

    // 4. Lighting
    this.initLights();

    // 5. Shield Group (Center Core)
    this.shieldGroup = new THREE.Group();
    this.initShieldCore();
    this.scene.add(this.shieldGroup);

    // 6. Monoliths (Orbiting Threat Rocks)
    this.initMonoliths();

    // 7. Volumetric Laser Cross (The Crimson Scanning Axis)
    this.laserGroup = new THREE.Group();
    this.initLaserCross();
    this.scene.add(this.laserGroup);

    // 8. Particle System
    this.initParticles();

    // 9. Event Listeners
    window.addEventListener('resize', this.onResize);
    window.addEventListener('mousemove', this.onMouseMove);

    // 10. Start Loop
    this.animate();
  }

  private initLights() {
    // Ambient fill (dark cyber blue/gray)
    const ambient = new THREE.AmbientLight('#080d1a', 1.8);
    this.scene.add(ambient);

    // Key directional light (cool white rim)
    const dirLight = new THREE.DirectionalLight('#475569', 1.2);
    dirLight.position.set(5, 10, 7);
    this.scene.add(dirLight);

    // Central Threat / Trust Point Light
    this.laserPointLight = new THREE.PointLight('#ff1e38', 4.5, 22, 1.5);
    this.laserPointLight.position.set(0, 0, 0.5);
    this.scene.add(this.laserPointLight);
  }

  private initShieldCore() {
    // Outer Crystalline Shield Geometry (Faceted 3D Polyhedron)
    const outerGeo = new THREE.IcosahedronGeometry(1.6, 0);
    // Perturb vertices slightly to look like a cut cyber gemstone shield
    const pos = outerGeo.attributes.position;
    for (let i = 0; i < pos.count; i++) {
      const y = pos.getY(i);
      // Lengthen slightly along Y axis for classic shield proportions
      pos.setY(i, y * 1.35);
    }
    outerGeo.computeVertexNormals();

    const outerMat = new THREE.MeshStandardMaterial({
      color: '#0f172a',
      roughness: 0.18,
      metalness: 0.92,
      flatShading: true,
      emissive: '#1e293b',
      emissiveIntensity: 0.2,
    });
    this.shieldOuterMesh = new THREE.Mesh(outerGeo, outerMat);
    this.shieldGroup.add(this.shieldOuterMesh);

    // Inner Cryptographic Energy Lattice
    const coreGeo = new THREE.OctahedronGeometry(1.05, 1);
    const coreMat = new THREE.MeshBasicMaterial({
      color: '#ff2a3a',
      wireframe: true,
      transparent: true,
      opacity: 0.75,
    });
    this.shieldCoreMesh = new THREE.Mesh(coreGeo, coreMat);
    this.shieldGroup.add(this.shieldCoreMesh);
  }

  private initMonoliths() {
    const monolithCount = 8;
    const colors = ['#0a0f1d', '#111827', '#090d16', '#131b2e', '#0b1220'];

    for (let i = 0; i < monolithCount; i++) {
      // Create jagged asteroid-like geometry
      const baseGeo = new THREE.DodecahedronGeometry(0.75 + Math.random() * 0.45, 1);
      const pos = baseGeo.attributes.position;
      // Procedural surface noise
      for (let j = 0; j < pos.count; j++) {
        const vx = pos.getX(j);
        const vy = pos.getY(j);
        const vz = pos.getZ(j);
        const noise = 1 + (Math.sin(vx * 4.5) * Math.cos(vy * 4.5) * 0.18);
        pos.setXYZ(j, vx * noise, vy * noise, vz * noise);
      }
      baseGeo.computeVertexNormals();

      const mat = new THREE.MeshStandardMaterial({
        color: colors[i % colors.length],
        roughness: 0.82,
        metalness: 0.25,
        flatShading: true,
      });

      const mesh = new THREE.Mesh(baseGeo, mat);
      const baseAngle = (i / monolithCount) * Math.PI * 2;
      const speed = (0.003 + Math.random() * 0.004) * (i % 2 === 0 ? 1 : -1);
      const yOffset = (Math.random() - 0.5) * 2.8;

      this.scene.add(mesh);
      this.monoliths.push({
        mesh,
        baseAngle,
        speed,
        yOffset,
        rotSpeed: new THREE.Vector3(
          (Math.random() - 0.5) * 0.015,
          (Math.random() - 0.5) * 0.015,
          (Math.random() - 0.5) * 0.015
        ),
      });
    }
  }

  private initLaserCross() {
    // 1. Horizontal Laser Beam (Thin glowing cylinder)
    const hGeo = new THREE.CylinderGeometry(0.022, 0.022, 36, 12);
    hGeo.rotateZ(Math.PI / 2);
    const laserMat = new THREE.MeshBasicMaterial({
      color: '#ff1e38',
      transparent: true,
      opacity: 0.95,
    });
    this.laserHMesh = new THREE.Mesh(hGeo, laserMat);
    this.laserGroup.add(this.laserHMesh);

    // 2. Vertical Laser Beam
    const vGeo = new THREE.CylinderGeometry(0.022, 0.022, 30, 12);
    this.laserVMesh = new THREE.Mesh(vGeo, laserMat.clone());
    this.laserGroup.add(this.laserVMesh);

    // 3. Volumetric Glow Core (Additive Halo)
    const haloGeo = new THREE.PlaneGeometry(5.2, 5.2);
    const haloMat = new THREE.ShaderMaterial({
      uniforms: {
        uColor: { value: new THREE.Color('#ff1e38') },
        uIntensity: { value: 1.2 },
      },
      vertexShader: `
        varying vec2 vUv;
        void main() {
          vUv = uv;
          gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
        }
      `,
      fragmentShader: `
        uniform vec3 uColor;
        uniform float uIntensity;
        varying vec2 vUv;
        void main() {
          float dist = distance(vUv, vec2(0.5));
          float alpha = clamp(0.08 / (dist * 3.5 + 0.04) - 0.1, 0.0, 1.0);
          gl_FragColor = vec4(uColor * uIntensity, alpha * 0.7);
        }
      `,
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    this.laserHalo = new THREE.Mesh(haloGeo, haloMat);
    this.laserGroup.add(this.laserHalo);
  }

  private initParticles() {
    const count = 1800;
    const geo = new THREE.BufferGeometry();
    const positions = new Float32Array(count * 3);
    const colors = new Float32Array(count * 3);

    for (let i = 0; i < count; i++) {
      const radius = 2.5 + Math.random() * 16;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(Math.random() * 2 - 1);

      const x = radius * Math.sin(phi) * Math.cos(theta);
      const y = radius * Math.sin(phi) * Math.sin(theta);
      const z = radius * Math.cos(phi);

      positions[i * 3] = x;
      positions[i * 3 + 1] = y;
      positions[i * 3 + 2] = z;

      // Color variation: mostly stardust white with occasional threat crimson/amber
      if (Math.random() > 0.85) {
        colors[i * 3] = 1.0; // Red
        colors[i * 3 + 1] = 0.15;
        colors[i * 3 + 2] = 0.25;
      } else {
        const val = 0.5 + Math.random() * 0.5;
        colors[i * 3] = val * 0.7;
        colors[i * 3 + 1] = val * 0.85;
        colors[i * 3 + 2] = val;
      }
    }

    geo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geo.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const mat = new THREE.PointsMaterial({
      size: 0.065,
      vertexColors: true,
      transparent: true,
      opacity: 0.85,
      blending: THREE.AdditiveBlending,
    });

    this.particleSystem = new THREE.Points(geo, mat);
    this.scene.add(this.particleSystem);
  }

  private onResize = () => {
    if (!this.container || this.isDestroyed) return;
    const width = this.container.clientWidth || window.innerWidth;
    const height = this.container.clientHeight || window.innerHeight;
    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(width, height);
  };

  private onMouseMove = (e: MouseEvent) => {
    const x = (e.clientX / window.innerWidth) * 2 - 1;
    const y = -(e.clientY / window.innerHeight) * 2 + 1;
    this.targetMouse.set(x, y);
  };

  /**
   * Set target scroll progress (0.0 to 6.0)
   */
  public setScrollProgress(progress: number) {
    this.targetProgress = Math.max(0, Math.min(6, progress));

    const now = Date.now();
    const dt = (now - this.lastScrollTime) / 1000;
    this.lastScrollTime = now;

    if (dt > 0.01) {
      const velocity = (this.targetProgress - this.currentProgress) / dt;
      cyberAudio.updateScrollVelocity(velocity);
    }
  }

  private animate = () => {
    if (this.isDestroyed) return;

    this.reqId = requestAnimationFrame(this.animate);

    // 1. Smooth interpolation of scroll progress
    this.currentProgress = THREE.MathUtils.lerp(this.currentProgress, this.targetProgress, 0.065);

    // 2. Smooth interpolation of mouse parallax
    this.currentMouse.lerp(this.targetMouse, 0.05);

    // 3. Interpolate camera keyframe parameters
    const kf = interpolateKeyframe(this.currentProgress);

    // Trigger chapter audio sound when integer chapter crossed
    const currentChapterIdx = Math.round(this.currentProgress);
    if (currentChapterIdx !== this.lastChapterReported) {
      this.lastChapterReported = currentChapterIdx;
      cyberAudio.playChapterPulse(currentChapterIdx);
    }

    // Apply camera position with subtle mouse parallax
    const parallaxX = this.currentMouse.x * 0.65;
    const parallaxY = this.currentMouse.y * 0.45;
    this.camera.position.set(
      kf.cameraPos.x + parallaxX,
      kf.cameraPos.y + parallaxY,
      kf.cameraPos.z
    );
    this.camera.lookAt(kf.cameraLookAt.x, kf.cameraLookAt.y, kf.cameraLookAt.z);

    // 4. Update Laser System
    (this.laserHMesh.material as THREE.MeshBasicMaterial).color.copy(kf.laserColor);
    (this.laserVMesh.material as THREE.MeshBasicMaterial).color.copy(kf.laserColor);
    this.laserPointLight.color.copy(kf.laserColor);
    this.laserPointLight.intensity = 4.2 * kf.laserIntensity;

    const haloUniforms = (this.laserHalo.material as THREE.ShaderMaterial).uniforms;
    haloUniforms.uColor.value.copy(kf.laserColor);
    haloUniforms.uIntensity.value = kf.laserIntensity;
    this.laserHalo.quaternion.copy(this.camera.quaternion);

    // 5. Update Central Shield
    this.shieldGroup.scale.setScalar(kf.shieldScale);
    this.shieldGroup.rotation.y += kf.rotationSpeed;
    this.shieldOuterMesh.rotation.x += 0.003;
    this.shieldCoreMesh.rotation.y -= kf.rotationSpeed * 1.5;
    this.shieldCoreMesh.rotation.z += 0.004;

    // Update inner core wireframe color matching laser
    (this.shieldCoreMesh.material as THREE.MeshBasicMaterial).color.copy(kf.laserColor);

    // 6. Update Monoliths (Orbiting Ring)
    const time = performance.now() * 0.001;
    this.monoliths.forEach((m) => {
      const angle = m.baseAngle + time * m.speed;
      const radius = kf.monolithSpread;
      m.mesh.position.set(
        Math.cos(angle) * radius,
        m.yOffset + Math.sin(time * 0.5 + m.baseAngle) * 0.4,
        Math.sin(angle) * (radius * 0.75)
      );
      m.mesh.rotation.x += m.rotSpeed.x;
      m.mesh.rotation.y += m.rotSpeed.y;
      m.mesh.rotation.z += m.rotSpeed.z;
    });

    // 7. Drift Particles
    if (this.particleSystem) {
      this.particleSystem.rotation.y += 0.0006;
      this.particleSystem.rotation.x += 0.0002;
    }

    // Render Scene
    this.renderer.render(this.scene, this.camera);
  };

  public destroy() {
    this.isDestroyed = true;
    cancelAnimationFrame(this.reqId);
    window.removeEventListener('resize', this.onResize);
    window.removeEventListener('mousemove', this.onMouseMove);

    // Dispose geometries & materials
    this.scene.traverse((obj) => {
      if (obj instanceof THREE.Mesh) {
        obj.geometry.dispose();
        if (Array.isArray(obj.material)) {
          obj.material.forEach((m) => m.dispose());
        } else {
          obj.material.dispose();
        }
      }
    });

    this.renderer.dispose();
    if (this.container && this.renderer.domElement) {
      this.container.removeChild(this.renderer.domElement);
    }
  }
}
