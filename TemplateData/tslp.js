// Taylor Swift LP 웹 버전 런타임
//  - 비밀번호로 암호 키를 만들고(PBKDF2) 암호화된 음원 · 이미지를 푼다(AES-GCM)
//  - 턴테이블 오디오 엔진: AudioWorklet이 회전 속도(rate)대로 재생 위치를 움직이며 샘플을 읽는다
//    (데스크톱 exe의 VinylAudioEngine과 같은 원리 — 45rpm, 가속 · 감속, 긁기(음수 rate), 런아웃 딸깍)
//  - 저음 · 고음은 BiquadFilter(lowshelf 150Hz / highshelf 5kHz), 마지막에 리미터
// 유니티 쪽에서는 Assets/Plugins/WebGL/TaylorLPWeb.jslib 이 window.TSLP 를 부른다.
(function () {
  'use strict';

  const TSLP = (window.TSLP = window.TSLP || {});
  const MAGIC = [0x54, 0x53, 0x4c, 0x50, 0x01]; // "TSLP" + 버전 1
  const CHECK_TEXT = 'taylor-lp-ok';
  const REMEMBER_KEY = 'tslp.unlock';

  // ------------------------------------------------------------------ 암호

  let aesKey = null;
  let keyInfo = null;

  function b64ToBytes(s) {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  async function openSealed(buffer, key) {
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < MAGIC.length; i++) {
      if (bytes[i] !== MAGIC[i]) throw new Error('암호화 형식이 아닌 파일');
    }
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(5, 17) }, key, bytes.subarray(17));
  }

  async function loadKeyInfo() {
    if (!keyInfo) {
      const res = await fetch('media/key.json', { cache: 'no-cache' });
      if (!res.ok) throw new Error('key.json ' + res.status);
      keyInfo = await res.json();
    }
    return keyInfo;
  }

  async function verify(key, info) {
    const plain = await openSealed(b64ToBytes(info.check).buffer, key);
    if (new TextDecoder().decode(plain) !== CHECK_TEXT) throw new Error('확인 문구 불일치');
  }

  /** 비밀번호로 잠금 해제. 틀리면 예외. remember면 이 기기(브라우저)에 키를 저장한다. */
  TSLP.unlock = async function (password, remember) {
    if (!window.crypto || !crypto.subtle) throw new Error('이 브라우저(또는 http 주소)에서는 암호 해제를 쓸 수 없어요.');
    const info = await loadKeyInfo();
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: b64ToBytes(info.salt), iterations: info.iterations }, base, 256));
    const key = await crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['decrypt']);
    await verify(key, info);
    aesKey = key;
    if (remember) {
      try { localStorage.setItem(REMEMBER_KEY, JSON.stringify({ salt: info.salt, key: bytesToB64(bits) })); } catch (e) { /* 저장 불가 */ }
    }
  };

  /** 이 기기에 기억해 둔 키로 잠금 해제. 성공하면 true. */
  TSLP.unlockRemembered = async function () {
    let saved = null;
    try { saved = JSON.parse(localStorage.getItem(REMEMBER_KEY) || 'null'); } catch (e) { saved = null; }
    if (!saved || !window.crypto || !crypto.subtle) return false;
    try {
      const info = await loadKeyInfo();
      if (saved.salt !== info.salt) throw new Error('사이트 비밀번호가 바뀜');
      const key = await crypto.subtle.importKey('raw', b64ToBytes(saved.key), 'AES-GCM', false, ['decrypt']);
      await verify(key, info);
      aesKey = key;
      return true;
    } catch (e) {
      TSLP.forget();
      return false;
    }
  };

  TSLP.forget = function () {
    try { localStorage.removeItem(REMEMBER_KEY); } catch (e) { /* 무시 */ }
  };

  async function fetchDecrypted(url, onProgress) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(url + ' ' + res.status);
    const total = Number(res.headers.get('Content-Length')) || 0;
    let buffer;
    if (onProgress && total && res.body && res.body.getReader) {
      const reader = res.body.getReader();
      const chunks = [];
      let received = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        received += value.length;
        onProgress(Math.min(1, received / total));
      }
      const all = new Uint8Array(received);
      let offset = 0;
      for (const c of chunks) { all.set(c, offset); offset += c.length; }
      buffer = all.buffer;
    } else {
      buffer = await res.arrayBuffer();
    }
    return openSealed(buffer, aesKey);
  }

  // ------------------------------------------------------------------ 유니티로 넘길 이미지 등

  const media = new Map();

  function notifyUnity(method, id) {
    const send = function () {
      if (window.unityInstance) window.unityInstance.SendMessage('TSLP Web Bridge', method, String(id));
      else setTimeout(send, 50);
    };
    send();
  }

  TSLP.requestMedia = function (id, path) {
    fetchDecrypted(path)
      .then(function (buffer) {
        media.set(id, new Uint8Array(buffer));
        notifyUnity('OnMediaReady', id);
      })
      .catch(function (err) {
        console.error('[TSLP] 파일을 열지 못함', path, err);
        notifyUnity('OnMediaFailed', id);
      });
  };

  TSLP.mediaSize = function (id) {
    const bytes = media.get(id);
    return bytes ? bytes.length : 0;
  };

  TSLP.takeMedia = function (id) {
    const bytes = media.get(id);
    media.delete(id);
    return bytes;
  };

  // ------------------------------------------------------------------ 턴테이블 오디오

  const WORKLET_SOURCE = String.raw`
class TSLPVinyl extends AudioWorkletProcessor {
  constructor() {
    super();
    this.version = 0; this.segments = []; this.tracks = []; this.length = 0;
    this.pos = 0; this.rate = 0; this.down = false; this.volume = 0.9; this.gain = 0;
    this.seq = 0; this.runOut = 0; this.click = 0; this.noise = 0x9E3779B9 | 0;
    this.frame = 0; this.cache = 0; this.lastWaiting = false;
    this.port.onmessage = (e) => {
      const m = e.data;
      switch (m.type) {
        case 'side':
          this.version = m.version; this.segments = m.segments; this.length = m.length;
          this.tracks = new Array(m.segments.length).fill(null);
          this.pos = 0; this.down = false; this.runOut = 0; this.cache = 0;
          break;
        case 'unload':
          this.version = m.version; this.segments = []; this.tracks = []; this.length = 0; this.down = false;
          break;
        case 'track':
          if (m.version === this.version) this.tracks[m.index] = { L: m.L, R: m.R, rate: m.sampleRate, frames: m.L.length };
          break;
        case 'missing':
          if (m.version === this.version) this.tracks[m.index] = { L: null, R: null, rate: 1, frames: 0 };
          break;
        case 'free':
          if (m.version === this.version) this.tracks[m.index] = null;
          break;
        case 'drop':
          this.pos = Math.max(0, Math.min(m.time, this.length)); this.down = true; this.seq = m.seq; this.runOut = 0;
          break;
        case 'lift': this.down = false; break;
        case 'rate': this.rate = m.rate; break;
        case 'volume': this.volume = m.volume; break;
      }
    };
  }
  nextNoise() {
    let x = this.noise; x ^= x << 13; x ^= x >>> 17; x ^= x << 5; this.noise = x | 0;
    return ((x >>> 0) & 0xFFFFFF) / 0x800000 - 1;
  }
  segmentIndex(pos) {
    const s = this.segments;
    if (s.length === 0) return -1;
    let i = this.cache < s.length ? this.cache : 0;
    if (!(pos >= s[i].start && (i + 1 >= s.length || pos < s[i + 1].start))) {
      i = 0;
      while (i + 1 < s.length && pos >= s[i + 1].start) i++;
      this.cache = i;
    }
    return i;
  }
  process(inputs, outputs) {
    const out = outputs[0];
    const L = out[0], R = out.length > 1 ? out[1] : null;
    const n = L.length;
    const hasSide = this.segments.length > 0;
    const step = this.rate / sampleRate;
    const target = this.down && hasSide ? this.volume : 0;
    let pos = this.pos, gain = this.gain, waiting = false;
    for (let f = 0; f < n; f++) {
      gain += (target - gain) * 0.004;
      let l = 0, r = 0, stall = false;
      if (hasSide) {
        const i = this.segmentIndex(pos);
        const seg = this.segments[i];
        if (pos >= seg.start && pos < seg.start + seg.length) {
          const t = this.tracks[i];
          if (!t) stall = this.down;
          else if (t.frames > 1 && gain > 1e-5) {
            const src = (pos - seg.start) * t.rate;
            if (src >= 0 && src < t.frames - 1) {
              const i0 = src | 0, fr = src - i0;
              l = t.L[i0] + (t.L[i0 + 1] - t.L[i0]) * fr;
              r = t.R[i0] + (t.R[i0 + 1] - t.R[i0]) * fr;
            }
          }
        }
        if (this.down && pos >= this.length) {
          const before = this.runOut;
          this.runOut += step;
          if (Math.floor(this.runOut / 1.8) !== Math.floor(before / 1.8)) this.click = 1;
          const hiss = this.nextNoise() * 0.003; l += hiss; r += hiss;
        }
        if (this.click > 1e-4) {
          const c = this.click * (this.nextNoise() * 0.22 + 0.3 * this.click);
          l += c; r += c; this.click *= 0.9985;
        }
      }
      L[f] = l * gain;
      if (R) R[f] = r * gain;
      if (stall) waiting = true;
      else if (this.down) {
        pos += step;
        if (pos < 0) pos = 0; else if (pos > this.length) pos = this.length;
      }
    }
    this.pos = pos; this.gain = gain;
    if ((++this.frame & 7) === 0 || waiting !== this.lastWaiting) {
      this.port.postMessage({ version: this.version, seq: this.seq, pos: pos, waiting: waiting });
      this.lastWaiting = waiting;
    }
    return true;
  }
}
registerProcessor('tslp-vinyl', TSLPVinyl);
`;

  class VinylAudio {
    constructor() {
      this.ctx = null;
      this.ready = null;
      this.segments = [];
      this.length = 0;
      this.version = 0;
      this.seq = 0;
      this.position = 0;
      this.rate = 0;
      this.down = false;
      this.waiting = false;
      this.progress = 1;
      this.decoded = new Map(); // 곡 번호 → 'ok' | 'missing'
      this.loading = -1;
    }

    init() {
      if (this.ready) return this.ready;
      const Ctx = window.AudioContext || window.webkitAudioContext;
      this.ctx = new Ctx({ latencyHint: 'playback' });
      const url = URL.createObjectURL(new Blob([WORKLET_SOURCE], { type: 'application/javascript' }));
      this.ready = this.ctx.audioWorklet.addModule(url).then(() => {
        const c = this.ctx;
        this.node = new AudioWorkletNode(c, 'tslp-vinyl', { numberOfInputs: 0, numberOfOutputs: 1, outputChannelCount: [2] });
        this.low = c.createBiquadFilter();
        this.low.type = 'lowshelf';
        this.low.frequency.value = 150;
        this.high = c.createBiquadFilter();
        this.high.type = 'highshelf';
        this.high.frequency.value = 5000;
        this.limiter = c.createDynamicsCompressor();
        this.limiter.threshold.value = -1;
        this.limiter.knee.value = 0;
        this.limiter.ratio.value = 20;
        this.limiter.attack.value = 0.002;
        this.limiter.release.value = 0.15;
        this.node.connect(this.low).connect(this.high).connect(this.limiter).connect(c.destination);
        this.node.port.onmessage = (e) => this.onWorklet(e.data);
      });
      // 브라우저는 사용자가 한 번 누르기 전까지 소리를 막는다 → 아무 입력에서나 다시 켠다
      const resume = () => { if (this.ctx.state !== 'running') this.ctx.resume(); };
      ['pointerdown', 'touchend', 'keydown', 'mousedown'].forEach((t) => document.addEventListener(t, resume, true));
      return this.ready;
    }

    get running() { return !!this.ctx && this.ctx.state === 'running'; }

    post(message, transfer) {
      this.init().then(() => this.node.port.postMessage(message, transfer || []));
    }

    loadSide(json) {
      const side = JSON.parse(json);
      this.version++;
      this.segments = side.segments;
      this.length = side.length;
      this.position = 0;
      this.down = false;
      this.waiting = false;
      this.decoded.clear();
      this.progress = 1;
      this.post({
        type: 'side', version: this.version, length: side.length,
        segments: side.segments.map((s) => ({ start: s.start, length: s.length })),
      });
      this.ensure(0);
    }

    unload() {
      this.version++;
      this.segments = [];
      this.length = 0;
      this.down = false;
      this.decoded.clear();
      this.post({ type: 'unload', version: this.version });
    }

    drop(time) {
      this.seq++;
      this.position = time;
      this.down = true;
      this.post({ type: 'drop', time: time, seq: this.seq });
      this.ensure(time);
    }

    lift() {
      this.down = false;
      this.post({ type: 'lift' });
    }

    setRate(rate) {
      this.rate = rate;
      this.post({ type: 'rate', rate: rate });
    }

    setVolume(volume) {
      this.post({ type: 'volume', volume: volume });
    }

    setTone(bass, treble) {
      this.init().then(() => {
        const t = this.ctx.currentTime;
        this.low.gain.setTargetAtTime(bass, t, 0.02);
        this.high.gain.setTargetAtTime(treble, t, 0.02);
      });
    }

    isBuffering() { return this.down && this.waiting; }

    onWorklet(m) {
      if (m.version !== this.version) return;
      if (m.seq === this.seq) this.position = m.pos; // 바늘을 막 옮긴 직후 도착한 예전 위치는 무시
      this.waiting = m.waiting;
      this.ensure(this.position);
    }

    segmentAt(t) {
      const s = this.segments;
      for (let i = 0; i < s.length; i++) if (s[i].start + s[i].length > t) return i;
      return s.length - 1;
    }

    /** 지금 곡 + 다음 곡(곡 시작 근처면 이전 곡도)만 풀어 두고 나머지는 메모리에서 뺀다. */
    ensure(t) {
      if (!this.segments.length) return;
      const i = this.segmentAt(t);
      const want = [i];
      if (i + 1 < this.segments.length) want.push(i + 1);
      if (i > 0 && t - this.segments[i].start < 8) want.push(i - 1);
      for (const k of Array.from(this.decoded.keys())) {
        if (!want.includes(k)) {
          this.decoded.delete(k);
          this.post({ type: 'free', version: this.version, index: k });
        }
      }
      if (this.loading >= 0) return;
      const next = want.find((k) => !this.decoded.has(k));
      if (next !== undefined) this.loadTrack(next);
    }

    async loadTrack(i) {
      const version = this.version;
      const seg = this.segments[i];
      this.loading = i;
      this.progress = 0;
      try {
        if (!seg.url) throw new Error('음원 없음');
        const plain = await fetchDecrypted(seg.url, (p) => { if (version === this.version) this.progress = p * 0.85; });
        await this.init();
        const audio = await this.ctx.decodeAudioData(plain);
        if (version !== this.version) return;
        const L = audio.getChannelData(0).slice();
        const R = (audio.numberOfChannels > 1 ? audio.getChannelData(1) : audio.getChannelData(0)).slice();
        this.decoded.set(i, 'ok');
        this.post({ type: 'track', version: version, index: i, L: L, R: R, sampleRate: audio.sampleRate }, [L.buffer, R.buffer]);
      } catch (err) {
        console.error('[TSLP] 음원을 열지 못함', seg && seg.url, err);
        if (version === this.version) {
          this.decoded.set(i, 'missing');
          this.post({ type: 'missing', version: version, index: i });
        }
      } finally {
        if (this.loading === i) this.loading = -1;
        this.progress = 1;
        if (version === this.version) this.ensure(this.position);
      }
    }
  }

  TSLP.audio = new VinylAudio();
})();
