import * as THREE from 'three';
import { RobotFace } from './RobotFace';
import { createGradientRingTexture } from './GradientRing';

export class CyberShieldRobot {
  public rootGroup: THREE.Group;
  public robotGroup: THREE.Group;
  public headGroup: THREE.Group;
  public torsoGroup: THREE.Group;

  // Face Engine
  public face: RobotFace;
  private ringTexture: THREE.CanvasTexture;

  // Materials
  private ceramicMat: THREE.MeshStandardMaterial;
  private darkJointMat: THREE.MeshStandardMaterial;
  private pedestalMat: THREE.MeshStandardMaterial;
  private faceMat: THREE.MeshBasicMaterial;
  private ringMat: THREE.MeshBasicMaterial;
  private ledMaterials: THREE.MeshBasicMaterial[] = [];

  // Pointers & Targets
  private targetHeadYaw: number = 0;
  private targetHeadPitch: number = 0;
  private currentHeadYaw: number = 0;
  private currentHeadPitch: number = 0;

  // Section State
  private targetQuoteMode: number = 0;
  private currentQuoteMode: number = 0;
  private sectionIndex: number = 0;

  constructor() {
    this.rootGroup = new THREE.Group();
    this.robotGroup = new THREE.Group();
    this.torsoGroup = new THREE.Group();
    this.headGroup = new THREE.Group();

    // 1. Initialize Face & Gradient Ring
    this.face = new RobotFace();
    this.ringTexture = createGradientRingTexture();

    // 2. Materials Setup
    this.ceramicMat = new THREE.MeshStandardMaterial({
      color: '#f6f4ee',
      roughness: 0.36,
      metalness: 0.05,
    });

    this.darkJointMat = new THREE.MeshStandardMaterial({
      color: '#222226',
      roughness: 0.55,
      metalness: 0.35,
    });

    this.pedestalMat = new THREE.MeshStandardMaterial({
      color: '#1a1a1d',
      roughness: 0.88,
      metalness: 0.12,
    });

    this.faceMat = new THREE.MeshBasicMaterial({
      map: this.face.texture,
    });

    this.ringMat = new THREE.MeshBasicMaterial({
      map: this.ringTexture,
      transparent: true,
      opacity: 0.96,
    });

    // 3. Build Pedestal & Contact Shadow
    this.buildPedestal();

    // 4. Build Body & Limbs
    this.buildBody();

    // 5. Build Head & Facial Screen
    this.buildHead();

    // Position entire robot on top of pedestal
    this.robotGroup.position.set(0.65, 0.35, 0); // Positioned slightly right of center
    this.rootGroup.add(this.robotGroup);
  }

  private buildPedestal() {
    // Charcoal Rectangular Plinth
    const plinthGeo = new THREE.BoxGeometry(4.2, 0.7, 3.4);
    const plinthMesh = new THREE.Mesh(plinthGeo, this.pedestalMat);
    plinthMesh.position.set(0.65, 0, 0);
    this.rootGroup.add(plinthMesh);

    // Soft Contact Shadow Plane
    const shadowGeo = new THREE.PlaneGeometry(3.6, 2.8);
    shadowGeo.rotateX(-Math.PI / 2);
    const shadowCanvas = document.createElement('canvas');
    shadowCanvas.width = 128;
    shadowCanvas.height = 128;
    const sCtx = shadowCanvas.getContext('2d');
    if (sCtx) {
      const grad = sCtx.createRadialGradient(64, 64, 10, 64, 64, 64);
      grad.addColorStop(0, 'rgba(0, 0, 0, 0.45)');
      grad.addColorStop(0.5, 'rgba(0, 0, 0, 0.18)');
      grad.addColorStop(1, 'rgba(0, 0, 0, 0)');
      sCtx.fillStyle = grad;
      sCtx.fillRect(0, 0, 128, 128);
    }
    const shadowTex = new THREE.CanvasTexture(shadowCanvas);
    const shadowMat = new THREE.MeshBasicMaterial({
      map: shadowTex,
      transparent: true,
      depthWrite: false,
    });
    const shadowMesh = new THREE.Mesh(shadowGeo, shadowMat);
    shadowMesh.position.set(0.65, 0.355, 0);
    this.rootGroup.add(shadowMesh);
  }

  private buildBody() {
    // Legs
    const legGeo = new THREE.CylinderGeometry(0.18, 0.22, 1.3, 16);
    const leftLeg = new THREE.Mesh(legGeo, this.ceramicMat);
    leftLeg.position.set(-0.45, 0.65, 0);
    const rightLeg = new THREE.Mesh(legGeo, this.ceramicMat);
    rightLeg.position.set(0.45, 0.65, 0);
    this.robotGroup.add(leftLeg, rightLeg);

    // Feet
    const footGeo = new THREE.BoxGeometry(0.38, 0.16, 0.55);
    const leftFoot = new THREE.Mesh(footGeo, this.ceramicMat);
    leftFoot.position.set(-0.45, 0.08, 0.08);
    const rightFoot = new THREE.Mesh(footGeo, this.ceramicMat);
    rightFoot.position.set(0.45, 0.08, 0.08);
    this.robotGroup.add(leftFoot, rightFoot);

    // Hip joint (Dark graphite cylinder)
    const hipGeo = new THREE.CylinderGeometry(0.35, 0.35, 0.3, 16);
    hipGeo.rotateZ(Math.PI / 2);
    const hip = new THREE.Mesh(hipGeo, this.darkJointMat);
    hip.position.set(0, 1.35, 0);
    this.robotGroup.add(hip);

    // Torso Group
    this.torsoGroup.position.set(0, 1.45, 0);
    this.robotGroup.add(this.torsoGroup);

    // Ceramic Torso Shell (Rounded tapered shape)
    const torsoGeo = new THREE.CylinderGeometry(0.72, 0.58, 1.45, 20);
    const torsoMesh = new THREE.Mesh(torsoGeo, this.ceramicMat);
    torsoMesh.position.set(0, 0.72, 0);
    this.torsoGroup.add(torsoMesh);

    // Three Small Chest Indicator LEDs (Green, Cyan, Amber)
    const ledGeo = new THREE.CircleGeometry(0.045, 12);
    const colors = ['#10b981', '#06b6d4', '#f59e0b'];
    for (let i = 0; i < 3; i++) {
      const ledMat = new THREE.MeshBasicMaterial({ color: colors[i] });
      this.ledMaterials.push(ledMat);
      const led = new THREE.Mesh(ledGeo, ledMat);
      led.position.set((i - 1) * 0.16, 0.82, 0.68);
      this.torsoGroup.add(led);
    }

    // Shoulder & Arm Joints
    const shoulderGeo = new THREE.SphereGeometry(0.18, 16, 16);
    const leftShoulder = new THREE.Mesh(shoulderGeo, this.darkJointMat);
    leftShoulder.position.set(-0.85, 1.25, 0);
    const rightShoulder = new THREE.Mesh(shoulderGeo, this.darkJointMat);
    rightShoulder.position.set(0.85, 1.25, 0);
    this.torsoGroup.add(leftShoulder, rightShoulder);

    // Arms
    const armGeo = new THREE.CylinderGeometry(0.12, 0.14, 1.1, 14);
    const leftArm = new THREE.Mesh(armGeo, this.ceramicMat);
    leftArm.position.set(-0.95, 0.65, 0.08);
    leftArm.rotation.z = -0.15;
    leftArm.rotation.x = 0.2;

    const rightArm = new THREE.Mesh(armGeo, this.ceramicMat);
    rightArm.position.set(0.95, 0.65, 0.08);
    rightArm.rotation.z = 0.15;
    rightArm.rotation.x = 0.2;

    this.torsoGroup.add(leftArm, rightArm);

    // Neck Joint (Dark graphite)
    const neckGeo = new THREE.CylinderGeometry(0.24, 0.28, 0.45, 16);
    const neck = new THREE.Mesh(neckGeo, this.darkJointMat);
    neck.position.set(0, 1.5, 0);
    this.torsoGroup.add(neck);
  }

  private buildHead() {
    // Head Group pivots atop the neck
    this.headGroup.position.set(0, 1.85, 0);
    this.torsoGroup.add(this.headGroup);

    // Ceramic Skull (Rounded box / cylinder approximation)
    const skullGeo = new THREE.BoxGeometry(1.65, 1.35, 1.25);
    const skull = new THREE.Mesh(skullGeo, this.ceramicMat);
    skull.position.set(0, 0.45, 0);
    this.headGroup.add(skull);

    // Rear Dark Housing
    const rearGeo = new THREE.BoxGeometry(1.45, 1.15, 0.35);
    const rear = new THREE.Mesh(rearGeo, this.darkJointMat);
    rear.position.set(0, 0.45, -0.55);
    this.headGroup.add(rear);

    // Face Screen (Glossy black display)
    const screenGeo = new THREE.PlaneGeometry(1.35, 1.05);
    const screenMesh = new THREE.Mesh(screenGeo, this.faceMat);
    screenMesh.position.set(0, 0.45, 0.635);
    this.headGroup.add(screenMesh);

    // Gradient Ring (Outer glowing bezel)
    const ringGeo = new THREE.PlaneGeometry(1.42, 1.12);
    const ringMesh = new THREE.Mesh(ringGeo, this.ringMat);
    ringMesh.position.set(0, 0.45, 0.638);
    this.headGroup.add(ringMesh);

    // Ear Pods (Left & Right cylinders)
    const earGeo = new THREE.CylinderGeometry(0.26, 0.26, 0.22, 18);
    earGeo.rotateZ(Math.PI / 2);

    const leftEar = new THREE.Mesh(earGeo, this.ceramicMat);
    leftEar.position.set(-0.92, 0.45, 0);
    const rightEar = new THREE.Mesh(earGeo, this.ceramicMat);
    rightEar.position.set(0.92, 0.45, 0);
    this.headGroup.add(leftEar, rightEar);
  }

  public setPointer(normX: number, normY: number) {
    // Clamped head tracking limits
    this.targetHeadYaw = THREE.MathUtils.clamp(normX * 0.42, -0.38, 0.38);
    this.targetHeadPitch = THREE.MathUtils.clamp(-normY * 0.28, -0.22, 0.22);

    // Eye gaze offset
    this.face.gazeX = THREE.MathUtils.clamp(normX * 0.8, -1.0, 1.0);
    this.face.gazeY = THREE.MathUtils.clamp(-normY * 0.8, -1.0, 1.0);
  }

  public setSection(sectionIndex: number) {
    this.sectionIndex = sectionIndex;
    if (sectionIndex === 2) {
      // Trust section: activate quotation mark face mode
      this.targetQuoteMode = 1.0;
    } else {
      this.targetQuoteMode = 0.0;
    }
  }

  public update(time: number) {
    // 1. Idle Body Breathing Bob & Sway
    const bob = Math.sin(time * 1.8) * 0.024;
    const sway = Math.sin(time * 1.2) * 0.012;
    this.torsoGroup.position.y = 1.45 + bob;
    this.torsoGroup.rotation.y = (this.sectionIndex === 0 ? -0.1 : 0) + sway;

    // 2. Smooth Head Yaw & Pitch Damping
    this.currentHeadYaw = THREE.MathUtils.lerp(this.currentHeadYaw, this.targetHeadYaw, 0.065);
    this.currentHeadPitch = THREE.MathUtils.lerp(this.currentHeadPitch, this.targetHeadPitch, 0.065);

    // Section-based head tilt offset: Section 01 tilts head gently to side, Section 02 & 03 straightens
    const tiltZ = this.sectionIndex === 0 ? 0.06 : 0;
    this.headGroup.rotation.set(this.currentHeadPitch, this.currentHeadYaw, tiltZ);

    // 3. Smooth Quote Mode Cross-fade
    this.currentQuoteMode = THREE.MathUtils.lerp(
      this.currentQuoteMode,
      this.targetQuoteMode,
      0.08
    );
    this.face.quoteModeProgress = this.currentQuoteMode;

    // 4. Update Face Canvas & Texture
    this.face.update(performance.now());
  }

  public dispose() {
    this.face.dispose();
    this.ringTexture.dispose();
    this.ceramicMat.dispose();
    this.darkJointMat.dispose();
    this.pedestalMat.dispose();
    this.faceMat.dispose();
    this.ringMat.dispose();
    this.ledMaterials.forEach((m) => m.dispose());
  }
}
