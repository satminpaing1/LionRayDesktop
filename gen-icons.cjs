const { PNG } = require('pngjs');
const pngToIco = require('png-to-ico').default || require('png-to-ico');
const fs = require('fs');
const path = require('path');

const iconsDir = path.join(__dirname, 'src-tauri', 'icons');
fs.mkdirSync(iconsDir, { recursive: true });

function dist(x1, y1, x2, y2) {
  return Math.sqrt((x1 - x2) ** 2 + (y1 - y2) ** 2);
}

function makePNG(size) {
  const png = new PNG({ width: size, height: size });
  const cx = size / 2, cy = size / 2;
  const R = size * 0.45;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const idx = (size * y + x) << 2;
      const nx = (x - cx) / R, ny = (y - cy) / R;

      let inShield = false;
      if (ny < -0.1) {
        const spread = 0.85 + ny * 1.2;
        if (Math.abs(nx) < spread) inShield = true;
      } else {
        const r = 0.85;
        if (nx * nx + (ny + 0.05) * (ny + 0.05) < r * r) inShield = true;
      }

      if (inShield) {
        const t = (ny + 1) / 2;
        const r = Math.round(245 - t * 20);
        const g = Math.round(158 + t * 10);
        const b = Math.round(11 + t * 5);
        png.data[idx] = r;
        png.data[idx + 1] = g;
        png.data[idx + 2] = b;
        png.data[idx + 3] = 255;

        let inPaw = false;
        if (dist(nx, ny, 0, 0.15) < 0.28) inPaw = true;
        const toeR = 0.13;
        const toeY = -0.2;
        if (dist(nx, ny, -0.22, toeY) < toeR) inPaw = true;
        if (dist(nx, ny, -0.07, toeY - 0.08) < toeR) inPaw = true;
        if (dist(nx, ny, 0.07, toeY - 0.08) < toeR) inPaw = true;
        if (dist(nx, ny, 0.22, toeY) < toeR) inPaw = true;

        if (inPaw) {
          png.data[idx] = 255;
          png.data[idx + 1] = 251;
          png.data[idx + 2] = 235;
          png.data[idx + 3] = 255;
        }
      } else {
        png.data[idx] = 0;
        png.data[idx + 1] = 0;
        png.data[idx + 2] = 0;
        png.data[idx + 3] = 0;
      }
    }
  }
  return png;
}

async function main() {
  const sizes = [16, 32, 48, 64, 128, 256];
  const pngBuffers = [];

  for (const size of sizes) {
    const pngBuf = PNG.sync.write(makePNG(size));
    const filePath = path.join(iconsDir, `${size}x${size}.png`);
    fs.writeFileSync(filePath, pngBuf);
    pngBuffers.push(pngBuf);
  }

  // also write standard names
  fs.writeFileSync(path.join(iconsDir, '32x32.png'), PNG.sync.write(makePNG(32)));
  fs.writeFileSync(path.join(iconsDir, '128x128.png'), PNG.sync.write(makePNG(128)));
  fs.writeFileSync(path.join(iconsDir, '128x128@2x.png'), PNG.sync.write(makePNG(256)));

  // generate proper ICO using png-to-ico (produces Windows-compatible ICO)
  const ico = await pngToIco(pngBuffers);
  fs.writeFileSync(path.join(iconsDir, 'icon.ico'), ico);

  console.log('Icons generated OK — golden shield + paw (' + ico.length + ' bytes ICO)');
}

main().catch(err => { console.error(err); process.exit(1); });
