import * as THREE from 'three';

/**
 * Offscreen 2D Canvas managing dynamic facial expressions for the 3D Robot:
 * - Two animated glowing pill eyes
 * - Natural blinking cycles
 * - Pointer gaze tracking
 * - Transition into an elegant quotation mark (") in Section 03 (Trust mode)
 */
export class RobotFace {
  public canvas: HTMLCanvasElement;
  public texture: THREE.CanvasTexture;
  private ctx: CanvasRenderingContext2D;

  private width = 512;
  private height = 512;

  // Face States
  public gazeX: number = 0; // -1 to 1
  public gazeY: number = 0; // -1 to 1
  public blinkProgress: number = 0; // 0 = open, 1 = fully closed
  public quoteModeProgress: number = 0; // 0 = eyes, 1 = quotation mark

  // Blink Timer
  private nextBlinkTime: number = 0;
  private isBlinking: boolean = false;
  private blinkStartTime: number = 0;

  constructor() {
    this.canvas = document.createElement('canvas');
    this.canvas.width = this.width;
    this.canvas.height = this.height;
    const ctx = this.canvas.getContext('2d');
    if (!ctx) throw new Error('Failed to get 2d context for RobotFace');
    this.ctx = ctx;

    this.texture = new THREE.CanvasTexture(this.canvas);
    this.texture.generateMipmaps = true;
    this.texture.minFilter = THREE.LinearMipmapLinearFilter;
    this.texture.magFilter = THREE.LinearFilter;

    this.scheduleNextBlink(performance.now());
    this.draw();
  }

  private scheduleNextBlink(now: number) {
    // Blink every 2.5 to 5.5 seconds
    this.nextBlinkTime = now + 2500 + Math.random() * 3000;
  }

  public update(time: number) {
    // Handle Blink Cycle
    if (!this.isBlinking && time >= this.nextBlinkTime) {
      this.isBlinking = true;
      this.blinkStartTime = time;
    }

    if (this.isBlinking) {
      const elapsed = time - this.blinkStartTime;
      const duration = 160; // 160ms total blink duration
      if (elapsed >= duration) {
        this.isBlinking = false;
        this.blinkProgress = 0;
        this.scheduleNextBlink(time);
      } else {
        // Sine curve: 0 -> 1 -> 0
        this.blinkProgress = Math.sin((elapsed / duration) * Math.PI);
      }
    }

    this.draw();
  }

  private draw() {
    const ctx = this.ctx;
    const w = this.width;
    const h = this.height;

    // Clear with deep glossy black
    ctx.fillStyle = '#060608';
    ctx.fillRect(0, 0, w, h);

    // Subtle facial glow
    const radial = ctx.createRadialGradient(w / 2, h / 2, 40, w / 2, h / 2, 220);
    radial.addColorStop(0, 'rgba(255, 120, 80, 0.08)');
    radial.addColorStop(1, 'rgba(0, 0, 0, 0)');
    ctx.fillStyle = radial;
    ctx.fillRect(0, 0, w, h);

    // 1. Draw Eyes (when quoteModeProgress < 1.0)
    if (this.quoteModeProgress < 0.99) {
      const eyeAlpha = 1.0 - this.quoteModeProgress;
      ctx.save();
      ctx.globalAlpha = eyeAlpha;

      // Base eye properties
      const eyeWidth = 52;
      const eyeHeight = Math.max(4, 76 * (1.0 - this.blinkProgress * 0.92));
      const eyeRadius = Math.min(eyeWidth, eyeHeight) / 2;
      const eyeSeparation = 72;

      // Gaze offset
      const offsetX = this.gazeX * 28;
      const offsetY = this.gazeY * 18;

      const drawEye = (cx: number, cy: number) => {
        ctx.beginPath();
        ctx.roundRect(
          cx - eyeWidth / 2,
          cy - eyeHeight / 2,
          eyeWidth,
          eyeHeight,
          eyeRadius
        );

        // Glowing white with soft blue-white rim
        ctx.shadowColor = '#ffffff';
        ctx.shadowBlur = 18;
        ctx.fillStyle = '#ffffff';
        ctx.fill();

        // Inner pupil tint
        ctx.shadowBlur = 0;
        ctx.fillStyle = '#f8f9fa';
        ctx.fill();
      };

      // Left Eye
      drawEye(w / 2 - eyeSeparation + offsetX, h / 2 + offsetY);
      // Right Eye
      drawEye(w / 2 + eyeSeparation + offsetX, h / 2 + offsetY);

      ctx.restore();
    }

    // 2. Draw Quotation Mark Mode (when quoteModeProgress > 0.0)
    if (this.quoteModeProgress > 0.01) {
      ctx.save();
      ctx.globalAlpha = this.quoteModeProgress;

      ctx.font = 'bold 160px "Plus Jakarta Sans", sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';

      // Soft coral/white glowing quotation mark
      ctx.shadowColor = 'rgba(255, 120, 80, 0.9)';
      ctx.shadowBlur = 24;
      ctx.fillStyle = '#ffffff';
      ctx.fillText('“', w / 2, h / 2 + 15);

      ctx.restore();
    }

    this.texture.needsUpdate = true;
  }

  public dispose() {
    this.texture.dispose();
  }
}
