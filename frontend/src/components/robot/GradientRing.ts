import * as THREE from 'three';

/**
 * Procedural Canvas Texture generating an Amber -> Orange -> Coral -> Pink
 * gradient rounded ring for the robot's face bezel.
 */
export function createGradientRingTexture(): THREE.CanvasTexture {
  const canvas = document.createElement('canvas');
  canvas.width = 512;
  canvas.height = 512;
  const ctx = canvas.getContext('2d');
  if (!ctx) throw new Error('Failed to create canvas 2d context for GradientRing');

  const w = canvas.width;
  const h = canvas.height;

  // Clear transparent
  ctx.clearRect(0, 0, w, h);

  // Gradient (Amber -> Orange -> Coral -> Vivid Pink)
  const grad = ctx.createLinearGradient(0, 0, w, h);
  grad.addColorStop(0.0, '#ffaa00'); // Amber
  grad.addColorStop(0.3, '#ff5500'); // Orange
  grad.addColorStop(0.65, '#ff2a6d'); // Coral
  grad.addColorStop(1.0, '#e0247d'); // Pink

  // Outer border with smooth corner radius
  const padding = 16;
  const strokeWidth = 24;
  const radius = 64;

  ctx.lineWidth = strokeWidth;
  ctx.strokeStyle = grad;
  ctx.shadowColor = '#ff4d4d';
  ctx.shadowBlur = 18;

  ctx.beginPath();
  ctx.roundRect(
    padding + strokeWidth / 2,
    padding + strokeWidth / 2,
    w - (padding + strokeWidth / 2) * 2,
    h - (padding + strokeWidth / 2) * 2,
    radius
  );
  ctx.stroke();

  // Fine inner accent line
  ctx.shadowBlur = 0;
  ctx.lineWidth = 3;
  ctx.strokeStyle = '#ffffff';
  ctx.globalAlpha = 0.55;
  ctx.stroke();

  const texture = new THREE.CanvasTexture(canvas);
  texture.generateMipmaps = true;
  texture.minFilter = THREE.LinearMipmapLinearFilter;
  texture.magFilter = THREE.LinearFilter;
  return texture;
}
