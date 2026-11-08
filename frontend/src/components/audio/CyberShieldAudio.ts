/**
 * CyberShield AI — Procedural Web Audio Engine
 * Zero external audio dependencies. 100% synthesized ambient drone,
 * dynamic filter sweeps, and chapter-transition radar pulses.
 */

class CyberShieldAudioEngine {
  private ctx: AudioContext | null = null;
  private isMuted: boolean = true;
  private isInitialized: boolean = false;

  // Synthesis Nodes
  private masterGain: GainNode | null = null;
  private droneOsc1: OscillatorNode | null = null;
  private droneOsc2: OscillatorNode | null = null;
  private droneFilter: BiquadFilterNode | null = null;
  private droneGain: GainNode | null = null;

  // Pulse synthesizer node
  private pulseGain: GainNode | null = null;

  private listeners: Set<(muted: boolean) => void> = new Set();

  constructor() {
    // Check initial preference from session
    if (typeof window !== 'undefined') {
      const saved = sessionStorage.getItem('cybershield_audio_muted');
      this.isMuted = saved !== null ? saved === 'true' : true;

      // Handle page visibility
      document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
          this.suspend();
        } else if (!this.isMuted && this.ctx && this.ctx.state === 'suspended') {
          this.ctx.resume();
        }
      });
    }
  }

  private initContext() {
    if (this.isInitialized && this.ctx) return;

    try {
      const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      this.ctx = new AudioCtx();

      // Master Output Gain
      this.masterGain = this.ctx.createGain();
      this.masterGain.gain.setValueAtTime(this.isMuted ? 0 : 0.25, this.ctx.currentTime);
      this.masterGain.connect(this.ctx.destination);

      // Lowpass Drone Filter (Cutoff dynamic on scroll)
      this.droneFilter = this.ctx.createBiquadFilter();
      this.droneFilter.type = 'lowpass';
      this.droneFilter.frequency.setValueAtTime(140, this.ctx.currentTime);
      this.droneFilter.Q.setValueAtTime(4.0, this.ctx.currentTime);

      // Drone Gain
      this.droneGain = this.ctx.createGain();
      this.droneGain.gain.setValueAtTime(0.35, this.ctx.currentTime);
      this.droneFilter.connect(this.droneGain);
      this.droneGain.connect(this.masterGain);

      // Sub-Bass Osc 1 (Sine @ 55Hz)
      this.droneOsc1 = this.ctx.createOscillator();
      this.droneOsc1.type = 'sine';
      this.droneOsc1.frequency.setValueAtTime(55, this.ctx.currentTime);
      this.droneOsc1.connect(this.droneFilter);
      this.droneOsc1.start();

      // Sub-Bass Osc 2 (Triangle @ 110Hz slightly detuned)
      this.droneOsc2 = this.ctx.createOscillator();
      this.droneOsc2.type = 'triangle';
      this.droneOsc2.frequency.setValueAtTime(110.4, this.ctx.currentTime);
      this.droneOsc2.connect(this.droneFilter);
      this.droneOsc2.start();

      // Pulse Gain for Chapter Pings
      this.pulseGain = this.ctx.createGain();
      this.pulseGain.gain.setValueAtTime(0, this.ctx.currentTime);
      this.pulseGain.connect(this.masterGain);

      this.isInitialized = true;
    } catch {
      // Audio not supported in this environment
      this.isInitialized = false;
    }
  }

  public async setMuted(muted: boolean): Promise<boolean> {
    this.isMuted = muted;
    sessionStorage.setItem('cybershield_audio_muted', String(muted));

    if (!muted) {
      this.initContext();
      if (this.ctx && this.ctx.state === 'suspended') {
        await this.ctx.resume();
      }
      if (this.masterGain && this.ctx) {
        this.masterGain.gain.cancelScheduledValues(this.ctx.currentTime);
        this.masterGain.gain.linearRampToValueAtTime(0.28, this.ctx.currentTime + 0.6);
      }
      this.playScanPing(660);
    } else {
      if (this.masterGain && this.ctx) {
        this.masterGain.gain.cancelScheduledValues(this.ctx.currentTime);
        this.masterGain.gain.linearRampToValueAtTime(0, this.ctx.currentTime + 0.4);
      }
    }

    this.notify();
    return this.isMuted;
  }

  public toggle(): boolean {
    this.setMuted(!this.isMuted);
    return this.isMuted;
  }

  public getMuted(): boolean {
    return this.isMuted;
  }

  public subscribe(cb: (muted: boolean) => void): () => void {
    this.listeners.add(cb);
    cb(this.isMuted);
    return () => this.listeners.delete(cb);
  }

  private notify() {
    this.listeners.forEach((cb) => cb(this.isMuted));
  }

  /**
   * Modulate the drone filter frequency according to camera or scroll velocity.
   * Gives an atmospheric volumetric surge during movement.
   */
  public updateScrollVelocity(velocity: number) {
    if (this.isMuted || !this.droneFilter || !this.ctx) return;
    const clampedVel = Math.min(Math.abs(velocity), 1.0);
    const targetFreq = 140 + clampedVel * 380; // 140Hz up to 520Hz
    this.droneFilter.frequency.setTargetAtTime(targetFreq, this.ctx.currentTime, 0.08);
  }

  /**
   * Synthesize a spatial cyber ping tone on chapter transitions
   */
  public playChapterPulse(chapterIndex: number) {
    if (this.isMuted || !this.ctx || !this.masterGain) return;
    try {
      const baseFreq = 440 + chapterIndex * 110; // Harmonic scale across chapters
      this.playScanPing(baseFreq);
    } catch {
      // Ignore audio synthesis errors
    }
  }

  private playScanPing(frequency: number) {
    if (!this.ctx || !this.masterGain) return;

    const osc = this.ctx.createOscillator();
    const gain = this.ctx.createGain();
    const filter = this.ctx.createBiquadFilter();

    osc.type = 'sine';
    osc.frequency.setValueAtTime(frequency, this.ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(frequency * 1.5, this.ctx.currentTime + 0.12);

    filter.type = 'bandpass';
    filter.frequency.setValueAtTime(frequency * 1.2, this.ctx.currentTime);
    filter.Q.setValueAtTime(6.0, this.ctx.currentTime);

    gain.gain.setValueAtTime(0, this.ctx.currentTime);
    gain.gain.linearRampToValueAtTime(0.18, this.ctx.currentTime + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + 0.45);

    osc.connect(filter);
    filter.connect(gain);
    gain.connect(this.masterGain);

    osc.start();
    osc.stop(this.ctx.currentTime + 0.5);
  }

  public suspend() {
    if (this.ctx && this.ctx.state === 'running') {
      this.ctx.suspend();
    }
  }
}

export const cyberAudio = new CyberShieldAudioEngine();
